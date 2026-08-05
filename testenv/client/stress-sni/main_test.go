package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloseResultsAfterWorkersFinish(t *testing.T) {
	results := make(chan WorkerResult)
	var workers sync.WaitGroup
	workers.Add(1)

	go func() {
		defer workers.Done()
		time.Sleep(20 * time.Millisecond)
		results <- WorkerResult{OK: true, Latency: time.Millisecond}
	}()

	closed := make(chan struct{})
	go func() {
		closeResultsAfterWorkers(&workers, results)
		close(closed)
	}()

	select {
	case result, ok := <-results:
		if !ok {
			t.Fatal("results closed before worker completed")
		}
		if !result.OK {
			t.Fatal("unexpected worker result")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for worker result")
	}

	select {
	case _, ok := <-results:
		if ok {
			t.Fatal("results remained open after workers completed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for results channel to close")
	}

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("closeResultsAfterWorkers did not return")
	}
}

// TestWorkerExitsWhenSendBlocked verifies that a worker blocked on
// a full results channel still exits promptly when stop is closed.
// Regression test for the goroutine leak where results<- had no
// select-on-stop path.
func TestWorkerExitsWhenSendBlocked(t *testing.T) {
	domains := []string{"example.com"}
	results := make(chan WorkerResult, 1) // tight buffer
	results <- WorkerResult{}             // pre-fill — next success blocks
	stop := make(chan struct{})
	var failed atomic.Int64
	var wg sync.WaitGroup

	dialTimeout := 3 * time.Second
	tlsTimeout := 3 * time.Second

	wg.Add(1)
	go func() {
		defer wg.Done()
		runWorker(domains, dialTimeout, tlsTimeout, nil, results, &failed, stop)
	}()

	// Allow one successful TLS handshake to fill the buffer, then
	// the next attempt should block on the select-on-stop guard.
	time.Sleep(500 * time.Millisecond)
	close(stop)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker blocked on full channel after stop — goroutine leaked")
	}

	// Drain the pre-filled slot so the channel garbage-collects.
	<-results
}
