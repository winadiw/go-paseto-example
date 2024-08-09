package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"go-paseto-example/httpcustom"

	"aidanwoods.dev/go-paseto"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type Admin struct {
	ID       int
	Username string
	Password string
}

// mockDB simulates a database
var mockDB = map[string]Admin{
	"admin@example.com": {
		ID:       1,
		Username: "admin@example.com",
		Password: "", // We'll set this in main()
	},
}

func mockQueryDB(username string) (Admin, bool) {
	admin, found := mockDB[username]
	return admin, found
}

func loginAdmin(username, password string) (string, paseto.V4SymmetricKey, error) {
	admin, found := mockQueryDB(username)
	if !found {
		return "", paseto.V4SymmetricKey{}, fmt.Errorf("invalid username or password")
	}

	// Verify the password
	err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password))
	if err != nil {
		return "", paseto.V4SymmetricKey{}, fmt.Errorf("invalid username or password")
	}

	// Generate PASETO v4 token
	symmetricKey, err := paseto.V4SymmetricKeyFromBytes([]byte("YELLOW SUBMARINE, BLACK WIZARDRY"))

	if err != nil {
		return "", paseto.V4SymmetricKey{}, fmt.Errorf("failed to create symmetric key: %v", err)
	}

	now := time.Now()
	exp := now.Add(120 * time.Minute)

	// Create a new token
	token := paseto.NewToken()

	// Set claims
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetExpiration(exp)
	token.SetAudience("admin")
	token.SetIssuer("your-app-name")
	token.SetJti("identifier")
	token.SetSubject("admin-auth")
	token.SetString("admin_id", strconv.Itoa(admin.ID))

	// Encrypt the token
	encrypted := token.V4Encrypt(symmetricKey, nil)

	fmt.Println("Symmetric Key (hex):", symmetricKey.ExportHex())
	return encrypted, symmetricKey, nil
}

func main() {
	// Set up our mock admin with a hashed password
	password := "admin_password"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	admin := mockDB["admin@example.com"]
	admin.Password = string(hashedPassword)
	mockDB["admin@example.com"] = admin

	// Attempt to login
	token, symmetricKey, err := loginAdmin("admin@example.com", "admin_password")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	fmt.Println("Login successful!")
	fmt.Println("Generated PASETO token:", token)

	// SIMULATE EXPIRY
	// time.Sleep(5 * time.Second)

	// Validate the generated token
	validatedToken, err := httpcustom.ValidateToken(token, symmetricKey)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	fmt.Println("\nToken validation successful!")

	// Extract and print claims from the validated token
	adminID, err := validatedToken.GetString("admin_id")
	if err != nil {
		log.Fatalf("Failed to get admin_id from token: %v", err)
	}
	fmt.Printf("Admin ID from token: %s\n", adminID)

	audience, err := validatedToken.GetAudience()
	if err != nil {
		log.Fatalf("Failed to get audience from token: %v", err)
	}
	fmt.Printf("Token audience: %s\n", audience)

	expirationTime, err := validatedToken.GetExpiration()
	if err != nil {
		log.Fatalf("Failed to get expiration time from token: %v", err)
	}
	fmt.Printf("Token expires at: %v\n", expirationTime)

	// Simulate a server, use middleware for validation
	r := mux.NewRouter()

	// Apply the middleware to a protected route
	r.HandleFunc("/protected", httpcustom.PasetoAuthMiddleware(httpcustom.ProtectedHandler)).Methods("GET")

	// Start the server
	fmt.Println("Server starting on :8080")
	http.ListenAndServe("127.0.0.1:8080", r)
}
