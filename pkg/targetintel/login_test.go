package targetintel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveCallback(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("handler blocked serving %s", target)
	}

	return rec
}

func assertNoResult(t *testing.T, results <-chan callbackResult) {
	t.Helper()
	select {
	case res := <-results:
		t.Fatalf("unexpected result delivered: %+v", res)
	default:
	}
}

func TestCallbackHandler(t *testing.T) {
	t.Parallel()
	h, results := newCallbackHandler("/", "good-state")

	rec := serveCallback(t, h, "/favicon.ico")
	assert.Equal(t, http.StatusNotFound, rec.Code, "a stray path is not the redirect")
	rec = serveCallback(t, h, "/favicon.ico?state=good-state&code=abc")
	assert.Equal(t, http.StatusNotFound, rec.Code, "only the registered path can deliver a code")
	assertNoResult(t, results)

	rec = serveCallback(t, h, "/")
	assert.Equal(t, http.StatusBadRequest, rec.Code, "a bare request to the redirect path is ignored")
	assertNoResult(t, results)

	rec = serveCallback(t, h, "/?state=bad-state&code=evil")
	assert.Equal(t, http.StatusBadRequest, rec.Code, "a code under the wrong state is rejected")
	rec = serveCallback(t, h, "/?state=bad-state&error=access_denied")
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an error under the wrong state cannot abort the login")
	assertNoResult(t, results)

	rec = serveCallback(t, h, "/?state=good-state&code=real-code")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "authenticated")

	rec = serveCallback(t, h, "/?state=good-state&code=second-code")
	assert.Equal(t, http.StatusOK, rec.Code, "a duplicate callback is answered without blocking")
	assert.Contains(t, rec.Body.String(), "already completed")

	select {
	case res := <-results:
		require.NoError(t, res.err)
		assert.Equal(t, "real-code", res.code, "the first valid callback wins")
	default:
		t.Fatal("valid callback delivered no result")
	}

	// After the result has been read, further callbacks still must not block.
	serveCallback(t, h, "/?state=good-state&code=third-code")
	assertNoResult(t, results)
}

func TestCallbackHandlerAuthorizationError(t *testing.T) {
	t.Parallel()
	h, results := newCallbackHandler("/", "good-state")

	rec := serveCallback(t, h, "/?state=good-state&error=access_denied")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "access_denied")

	select {
	case res := <-results:
		require.Error(t, res.err)
		assert.Contains(t, res.err.Error(), "authorization denied: access_denied")
		assert.Empty(t, res.code)
	default:
		t.Fatal("authorization error delivered no result")
	}
}
