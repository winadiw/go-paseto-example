package httpcustom

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"aidanwoods.dev/go-paseto"
)

// Global symmetric key (in a real app, manage this securely)
var globalSymmetricKey paseto.V4SymmetricKey

// Add token claims to request context
type contextKey string

const tokenClaimsKey contextKey = "token_claims"

func init() {
	var err error
	globalSymmetricKey, err = paseto.V4SymmetricKeyFromBytes([]byte("YELLOW SUBMARINE, BLACK WIZARDRY"))
	if err != nil {
		panic(fmt.Sprintf("Failed to create symmetric key: %v", err))
	}
}

// PasetoAuthMiddleware validates the PASETO token in the Authorization header
func PasetoAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token, err := ValidateToken(tokenString, globalSymmetricKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), tokenClaimsKey, token.Claims())

		// Call the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func ValidateToken(tokenString string, symmetricKey paseto.V4SymmetricKey) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.ForAudience("admin"))
	parser.AddRule(paseto.IdentifiedBy("identifier"))
	parser.AddRule(paseto.Subject("admin-auth"))
	token, err := parser.ParseV4Local(symmetricKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %v", err)
	}

	return token, nil
}

// ProtectedHandler example protected handler
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(tokenClaimsKey).(map[string]interface{})
	if !ok {
		http.Error(w, "Failed to get token claims", http.StatusInternalServerError)
		return
	}

	adminID, ok := claims["admin_id"].(string)
	if !ok {
		http.Error(w, "Failed to get admin_id", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Protected resource accessed by admin ID: %s", adminID)
}
