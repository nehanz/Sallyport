package sallyport

import (
	"net/http"
	"time"

	"github.com/nehanz/sallyport/internal/ssrf"
)

func NewSafeClient(timeout time.Duration) *http.Client {
	return ssrf.NewSafeClient(timeout)
}

func NewSafeTransport() *http.Transport {
	return ssrf.NewSafeTransport()
}
