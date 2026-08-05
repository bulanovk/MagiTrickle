package v1

import (
	"fmt"
	"net/http"
	"strconv"

	"magitrickle/api/utils"
	"magitrickle/api/v1/types"
	"magitrickle/models"

	"github.com/rs/zerolog/log"
)

// GetSNISnifferConfig
//
//	@Summary		Получить конфигурацию SNI-снифера
//	@Description	Возвращает текущую runtime-конфигурацию NFQUEUE-снифера
//	@Tags			sniffer
//	@Produce		json
//	@Success		200	{object}	types.SNISnifferConfigRes
//	@Router			/api/v1/sniffer/config [get]
func (h *Handler) GetSNISnifferConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.app.SNISnifferConfig()
	utils.WriteJson(w, http.StatusOK, types.SNISnifferConfigRes{
		Enabled:        cfg.Enabled,
		QueueNum:       cfg.QueueNum,
		MaxQueueLen:    cfg.MaxQueueLen,
		MaxPacketLen:   cfg.MaxPacketLen,
		EnableTLS:      cfg.EnableTLS,
		EnableHTTP:     cfg.EnableHTTP,
		EnableHTTP2:    cfg.EnableHTTP2,
		AdditionalTTL:  cfg.AdditionalTTL,
		LogDNSMismatch: cfg.LogDNSMismatch,
	})
}

// PutSNISnifferConfig
//
//	@Summary		Обновить конфигурацию SNI-снифера
//	@Description	Применяет новую конфигурацию снифера. Изменения вступают в силу после перезапуска MagiTrickle.
//	@Tags			sniffer
//	@Accept			json
//	@Produce		json
//	@Param			save	query		bool							false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.SNISnifferConfigRes		true	"Новая конфигурация"
//	@Success		200		{object}	types.SNISnifferConfigRes
//	@Failure		400		{object}	types.ErrorRes
//	@Router			/api/v1/sniffer/config [put]
func (h *Handler) PutSNISnifferConfig(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.SNISnifferConfigRes](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	save := r.URL.Query().Get("save") == "true"
	if err := h.app.SetSNISnifferConfig(sniConfigFromReq(req), save); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update sniffer config: %v", err))
		return
	}
	log.Info().
		Bool("enabled", req.Enabled).
		Bool("save", save).
		Msg("SNI sniffer config updated")
	h.GetSNISnifferConfig(w, r)
}

// GetSNISnifferStats
//
//	@Summary		Получить метрики SNI-снифера
//	@Description	Возвращает атомарные счётчики и packets-per-second. Если снифер выключен или модули ядра отсутствуют, вернёт Active=false и 200.
//	@Tags			sniffer
//	@Produce		json
//	@Success		200	{object}	types.SNISnifferStatsRes
//	@Router			/api/v1/sniffer/stats [get]
func (h *Handler) GetSNISnifferStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.app.SNISnifferStats()
	res := types.SNISnifferStatsRes{
		PacketsTotal:      stats.PacketsTotal,
		HitsTotal:         stats.HitsTotal,
		MissesTotal:       stats.MissesTotal,
		ParseFailures:     stats.ParseFailures,
		EmptyPayloadTotal: stats.EmptyPayloadTotal,
		StitchedHits:      stats.StitchedHits,
		PacketsPerSec:     stats.PacketsPerSec,
		StartedAt:         stats.StartedAt,
		Active:            err == nil && stats.Active,
	}
	utils.WriteJson(w, http.StatusOK, res)
}

// GetSNISnifferRecent
//
//	@Summary		Получить последние SNI-наблюдения
//	@Description	Возвращает список последних наблюдений (dst IP → домен), записанных снифером.
//	@Tags			sniffer
//	@Produce		json
//	@Param			limit	query		int	false	"Максимум наблюдений (по умолчанию 50)"
//	@Success		200		{object}	types.SNISnifferRecentRes
//	@Router			/api/v1/sniffer/recent [get]
func (h *Handler) GetSNISnifferRecent(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	obs, err := h.app.SNISnifferRecent(limit)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list SNI observations: %v", err))
		return
	}
	out := types.SNISnifferRecentRes{
		Observations: make([]types.SNISnifferObservationRes, len(obs)),
	}
	for i, o := range obs {
		out.Observations[i] = types.SNISnifferObservationRes{
			IP:        o.IP,
			Domain:    o.Domain,
			Observed:  o.Observed,
			ExpiresIn: o.ExpiresIn,
		}
	}
	utils.WriteJson(w, http.StatusOK, out)
}

func sniConfigFromReq(r types.SNISnifferConfigRes) models.AppConfigSNISniffer {
	return models.AppConfigSNISniffer{
		Enabled:        r.Enabled,
		QueueNum:       r.QueueNum,
		MaxQueueLen:    r.MaxQueueLen,
		MaxPacketLen:   r.MaxPacketLen,
		EnableTLS:      r.EnableTLS,
		EnableHTTP:     r.EnableHTTP,
		EnableHTTP2:    r.EnableHTTP2,
		AdditionalTTL:  r.AdditionalTTL,
		LogDNSMismatch: r.LogDNSMismatch,
	}
}
