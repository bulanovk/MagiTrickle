package recordsCache

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"
)

type Address struct {
	Address  net.IP
	Deadline time.Time
}

type Alias struct {
	Alias    string
	Deadline time.Time
}

type Records struct {
	locker sync.RWMutex

	// Раздельные map'ы вместо map[string]interface{}
	addresses map[string][]*Address
	aliases   map[string]*Alias

	// Обратный индекс: alias → []domains, которые на него ссылаются
	reverseAliases map[string][]string

	// Последнее наблюдение SNI-снифера: dst IP → (domain, when).
	// Используется для логирования disagreement между SNI и DNS,
	// а позже для GET /sniffer/recent. Один IP — одно наблюдение;
	// повторный sniff перезаписывает предыдущее.
	sniObservations map[string]sniObservation
}

// sniObservation is a single (domain, time) pair recorded by the
// SNI sniffer. The IP key lives in Records.sniObservations; we only
// store the most recent observation per IP.
type sniObservation struct {
	Domain   string
	Observed time.Time
}

func (r *Records) AddAlias(domainName, alias string, ttl uint32) {
	if domainName == alias {
		return
	}

	r.locker.Lock()
	defer r.locker.Unlock()

	deadline := time.Now().Add(time.Duration(ttl) * time.Second)

	// Удаляем старый reverse alias если был
	if oldAlias, ok := r.aliases[domainName]; ok {
		r.removeReverseAlias(oldAlias.Alias, domainName)
	}

	r.aliases[domainName] = &Alias{
		Alias:    alias,
		Deadline: deadline,
	}

	// Добавляем reverse alias
	r.reverseAliases[alias] = append(r.reverseAliases[alias], domainName)
}

func (r *Records) removeReverseAlias(alias, domainName string) {
	domains := r.reverseAliases[alias]
	for i, d := range domains {
		if d == domainName {
			// Удаляем элемент без сохранения порядка
			domains[i] = domains[len(domains)-1]
			r.reverseAliases[alias] = domains[:len(domains)-1]
			break
		}
	}
	if len(r.reverseAliases[alias]) == 0 {
		delete(r.reverseAliases, alias)
	}
}

func (r *Records) AddAddress(domainName string, addr net.IP, ttl uint32) {
	r.locker.Lock()
	defer r.locker.Unlock()

	deadline := time.Now().Add(time.Duration(ttl) * time.Second)

	addresses := r.addresses[domainName]
	for _, aRecord := range addresses {
		if bytes.Equal(aRecord.Address, addr) {
			aRecord.Deadline = deadline
			return
		}
	}

	r.addresses[domainName] = append(addresses, &Address{
		Address:  addr,
		Deadline: deadline,
	})
}

// GetAliases возвращает все домены, которые ссылаются на данный (прямо или транзитивно)
func (r *Records) GetAliases(domainName string) []string {
	r.locker.RLock()
	defer r.locker.RUnlock()

	result := []string{domainName}
	queue := []string{domainName}
	seen := make(map[string]struct{})
	seen[domainName] = struct{}{}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, pointing := range r.reverseAliases[current] {
			if _, ok := seen[pointing]; ok {
				continue
			}
			seen[pointing] = struct{}{}
			result = append(result, pointing)
			queue = append(queue, pointing)
		}
	}

	return result
}

func (r *Records) GetAddresses(domainName string) []*Address {
	r.locker.RLock()
	defer r.locker.RUnlock()

	now := time.Now()
	seen := make(map[string]struct{})
	seen[domainName] = struct{}{}

	for {
		if addresses, ok := r.addresses[domainName]; ok && len(addresses) > 0 {
			// Фильтруем просроченные адреса (только чтение, без удаления)
			var valid []*Address
			for _, addr := range addresses {
				if !now.After(addr.Deadline) {
					valid = append(valid, addr)
				}
			}
			if len(valid) > 0 {
				return valid
			}
		}

		alias, ok := r.aliases[domainName]
		if !ok || now.After(alias.Deadline) {
			return nil
		}

		// Защита от циклов
		if _, ok := seen[alias.Alias]; ok {
			return nil
		}
		seen[alias.Alias] = struct{}{}
		domainName = alias.Alias
	}
}

func (r *Records) ListKnownDomains() []string {
	r.locker.RLock()
	defer r.locker.RUnlock()

	// Собираем уникальные домены из обоих map'ов
	domains := make(map[string]struct{}, len(r.addresses)+len(r.aliases))

	for name := range r.addresses {
		domains[name] = struct{}{}
	}

	for name := range r.aliases {
		domains[name] = struct{}{}
	}

	result := make([]string, 0, len(domains))
	for name := range domains {
		result = append(result, name)
	}
	return result
}

// cleanupRecords удаляет истёкшие записи
func (r *Records) cleanupRecords() {
	r.locker.Lock()
	defer r.locker.Unlock()

	now := time.Now()

	// Очистка адресов
	for name, addresses := range r.addresses {
		idx := 0
		for _, addr := range addresses {
			if !now.After(addr.Deadline) {
				addresses[idx] = addr
				idx++
			}
		}
		if idx == 0 {
			delete(r.addresses, name)
		} else {
			r.addresses[name] = addresses[:idx]
		}
	}

	// Очистка алиасов
	for name, alias := range r.aliases {
		if now.After(alias.Deadline) {
			r.removeReverseAlias(alias.Alias, name)
			delete(r.aliases, name)
		}
	}

	// Очистка SNI-наблюдений старше SNIObservationTTL.
	for ip, obs := range r.sniObservations {
		if now.Sub(obs.Observed) > SNIObservationTTL {
			delete(r.sniObservations, ip)
		}
	}
}

// SNIObservationTTL is how long an SNI observation lives in the
// records cache before being purged. Chosen equal to the DNS path's
// default additional TTL (1 hour) so disagreement detection has the
// same temporal horizon as DNS records.
const SNIObservationTTL = 1 * time.Hour

// ObserveSNI records the most recent (domain, now) pair for the
// given destination IP. Calling ObserveSNI twice with the same IP
// overwrites the previous observation — only the latest matters for
// disagreement detection.
func (r *Records) ObserveSNI(ip string, domain string) {
	if ip == "" || domain == "" {
		return
	}
	r.locker.Lock()
	defer r.locker.Unlock()
	r.sniObservations[ip] = sniObservation{
		Domain:   domain,
		Observed: time.Now(),
	}
}

// LastSNIDomain returns the most recent SNI observation for the IP
// and whether one exists. The boolean is false when no observation
// has been recorded (or it has been purged).
func (r *Records) LastSNIDomain(ip string) (string, bool) {
	r.locker.RLock()
	defer r.locker.RUnlock()
	obs, ok := r.sniObservations[ip]
	if !ok {
		return "", false
	}
	return obs.Domain, true
}

// ListSNIObservations returns a snapshot of all live SNI observations
// for the upcoming /sniffer/recent API. The returned slice is a copy
// — callers may mutate it freely.
func (r *Records) ListSNIObservations() []SNIObservation {
	r.locker.RLock()
	defer r.locker.RUnlock()
	out := make([]SNIObservation, 0, len(r.sniObservations))
	now := time.Now()
	for ip, obs := range r.sniObservations {
		if now.Sub(obs.Observed) > SNIObservationTTL {
			continue
		}
		out = append(out, SNIObservation{
			IP:        ip,
			Domain:    obs.Domain,
			Observed:  obs.Observed,
			ExpiresIn: SNIObservationTTL - now.Sub(obs.Observed),
		})
	}
	return out
}

// SNIObservation is the public view of a single SNI observation,
// returned by ListSNIObservations.
type SNIObservation struct {
	IP        string
	Domain    string
	Observed  time.Time
	ExpiresIn time.Duration
}

// StartCleanup запускает фоновую очистку с заданным интервалом
func (r *Records) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.cleanupRecords()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func New() *Records {
	return &Records{
		addresses:       make(map[string][]*Address),
		aliases:         make(map[string]*Alias),
		reverseAliases:  make(map[string][]string),
		sniObservations: make(map[string]sniObservation),
	}
}
