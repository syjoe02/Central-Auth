package middleware

import (
	"log"

	"central-auth/internal/service"

	"github.com/gin-gonic/gin"
)

// BFFAPIBridgeMiddleware bridges the BFF cookie session layer with the API
// proxy layer. It reads the __session cookie, resolves it to the caller's
// kratosID and deviceID via ResolveSession, and stores them in the Gin
// context so ProxyHandler can inject them as trusted headers.
//
// Requests without a valid __session are passed through unchanged; the
// proxy handler will forward them without X-User-ID (public/anonymous access).
func BFFAPIBridgeMiddleware(bffService service.BFFServiceI) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf(
			"[BFF-BRIDGE] path=%s",
			c.Request.URL.Path,
		)

		cookieVal, err := c.Cookie(bffSessionCookieName)
		log.Printf(
			"[BFF-BRIDGE] cookie_exists=%v",
			err == nil && cookieVal != "",
		)

		if err != nil || cookieVal == "" {
			log.Printf("[BFF-BRIDGE] path=%s: no __session cookie, forwarding as anonymous", c.Request.URL.Path)
			c.Next()
			return
		}

		_, kratosID, deviceID, err := bffService.ResolveSession(c.Request.Context(), cookieVal)
		if err != nil {
			log.Printf("[BFF-BRIDGE] path=%s: ResolveSession error: %v", c.Request.URL.Path, err)
			c.Next()
			return
		}

		prefix := kratosID
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		log.Printf("[BFF-BRIDGE] path=%s: identity resolved kratosID_prefix=%s", c.Request.URL.Path, prefix)
		c.Set("bff.userID", kratosID)
		if deviceID != "" {
			c.Set("bff.deviceID", deviceID)
		}
		c.Next()
	}
}
