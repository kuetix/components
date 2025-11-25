package jwt

import (
	"os"
	"testing"

	"github.com/kuetix/components/tests"
	"github.com/kuetix/engine"
	"github.com/kuetix/engine/boot"
)

func init() {
	println("init")
	println(os.Getwd())
	tests.BootstrapTest()
}

func TestJwt(t *testing.T) {
	t.Log("TestBool")

	responses := engine.RunWorkflow(&boot.Options{
		EngineName: "tests",
		Workflow:   "jwt/tests/assert_jwt_test",
		Amount:     1,
		Args: []string{
			"jwtIssuer=testIssuer",
			"encryptedId=1234567890",
		},
	})

	for _, response := range responses {
		if response == nil {
			t.Fatalf("Expected response to be not nil, got %v", response)
		}
		if response.Response == true {
			t.Fatalf("Expected response to be false, got %v", response.Response)
		}
	}
}
