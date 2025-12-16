package xjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// testKey generates an ECDSA P-256 key pair for testing
func testKey(t *testing.T) (*jose.JSONWebKey, *jose.JSONWebKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	priv := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "test-key",
		Algorithm: string(jose.ES256),
	}
	pub := &jose.JSONWebKey{
		Key:       privateKey.Public(),
		KeyID:     "test-key",
		Algorithm: string(jose.ES256),
	}
	return priv, pub
}

// signJWT creates a signed JWT with the given claims
func signJWT(t *testing.T, privateKey *jose.JSONWebKey, claims map[string]interface{}) []byte {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := jws.CompactSerialize()
	require.NoError(t, err)

	return []byte(token)
}

func TestVerify_ClockTolerance_NotBefore(t *testing.T) {
	priv, pub := testKey(t)
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*pub}}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		nbfOffset      time.Duration // offset from "now" for nbf claim
		clockTolerance time.Duration
		expectError    bool
	}{
		{
			name:           "nbf in past - should pass",
			nbfOffset:      -10 * time.Second,
			clockTolerance: 0,
			expectError:    false,
		},
		{
			name:           "nbf exactly now - should pass",
			nbfOffset:      0,
			clockTolerance: 0,
			expectError:    false,
		},
		{
			name:           "nbf 2s in future without tolerance - should fail",
			nbfOffset:      2 * time.Second,
			clockTolerance: 0,
			expectError:    true,
		},
		{
			name:           "nbf 2s in future with 2s tolerance - should pass",
			nbfOffset:      2 * time.Second,
			clockTolerance: 2 * time.Second,
			expectError:    false,
		},
		{
			name:           "nbf 2s in future with 3s tolerance - should pass",
			nbfOffset:      2 * time.Second,
			clockTolerance: 3 * time.Second,
			expectError:    false,
		},
		{
			name:           "nbf 5s in future with 2s tolerance - should fail",
			nbfOffset:      5 * time.Second,
			clockTolerance: 2 * time.Second,
			expectError:    true,
		},
		{
			name:           "nbf 1s in future with 1s tolerance - should pass (boundary)",
			nbfOffset:      1 * time.Second,
			clockTolerance: 1 * time.Second,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"iss": "test-issuer",
				"sub": "test-subject",
				"aud": "test-audience",
				"exp": now.Add(1 * time.Hour).Unix(),
				"nbf": now.Add(tt.nbfOffset).Unix(),
			}

			token := signJWT(t, priv, claims)

			_, err := Verify(token, VerifyConfig{
				KeySet:         keySet,
				ClockTolerance: tt.clockTolerance,
				Now:            func() time.Time { return now },
			})

			if tt.expectError {
				require.Error(t, err)
				verifyErr, ok := err.(*VerifyErr)
				require.True(t, ok, "expected VerifyErr")
				require.Equal(t, JWT_EXPIRED, verifyErr.XJWTVerifyReason())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerify_ClockTolerance_Expiry(t *testing.T) {
	priv, pub := testKey(t)
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*pub}}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		expOffset      time.Duration // offset from "now" for exp claim
		clockTolerance time.Duration
		expectError    bool
	}{
		{
			name:           "exp in future - should pass",
			expOffset:      10 * time.Second,
			clockTolerance: 0,
			expectError:    false,
		},
		{
			name:           "exp 2s in past without tolerance - should fail",
			expOffset:      -2 * time.Second,
			clockTolerance: 0,
			expectError:    true,
		},
		{
			name:           "exp 2s in past with 2s tolerance - should pass (boundary, now equals exp+tolerance)",
			expOffset:      -2 * time.Second,
			clockTolerance: 2 * time.Second,
			expectError:    false,
		},
		{
			name:           "exp 2s in past with 3s tolerance - should pass",
			expOffset:      -2 * time.Second,
			clockTolerance: 3 * time.Second,
			expectError:    false,
		},
		{
			name:           "exp 5s in past with 2s tolerance - should fail",
			expOffset:      -5 * time.Second,
			clockTolerance: 2 * time.Second,
			expectError:    true,
		},
		{
			name:           "exp 1s in past with 2s tolerance - should pass",
			expOffset:      -1 * time.Second,
			clockTolerance: 2 * time.Second,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"iss": "test-issuer",
				"sub": "test-subject",
				"aud": "test-audience",
				"exp": now.Add(tt.expOffset).Unix(),
				"nbf": now.Add(-1 * time.Hour).Unix(), // nbf well in the past
			}

			token := signJWT(t, priv, claims)

			_, err := Verify(token, VerifyConfig{
				KeySet:         keySet,
				ClockTolerance: tt.clockTolerance,
				Now:            func() time.Time { return now },
			})

			if tt.expectError {
				require.Error(t, err)
				verifyErr, ok := err.(*VerifyErr)
				require.True(t, ok, "expected VerifyErr")
				require.Equal(t, JWT_EXPIRED, verifyErr.XJWTVerifyReason())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerify_ClockTolerance_BothNbfAndExp(t *testing.T) {
	priv, pub := testKey(t)
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*pub}}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("token slightly early and tolerance allows it", func(t *testing.T) {
		// Token that starts 1s in the future and expires 1 hour from now
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"exp": now.Add(1 * time.Hour).Unix(),
			"nbf": now.Add(1 * time.Second).Unix(),
		}

		token := signJWT(t, priv, claims)

		// Without tolerance, should fail
		_, err := Verify(token, VerifyConfig{
			KeySet: keySet,
			Now:    func() time.Time { return now },
		})
		require.Error(t, err)

		// With 2s tolerance, should pass
		_, err = Verify(token, VerifyConfig{
			KeySet:         keySet,
			ClockTolerance: 2 * time.Second,
			Now:            func() time.Time { return now },
		})
		require.NoError(t, err)
	})

	t.Run("token slightly expired and tolerance allows it", func(t *testing.T) {
		// Token that started 1 hour ago and expired 1s ago
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"exp": now.Add(-1 * time.Second).Unix(),
			"nbf": now.Add(-1 * time.Hour).Unix(),
		}

		token := signJWT(t, priv, claims)

		// Without tolerance, should fail
		_, err := Verify(token, VerifyConfig{
			KeySet: keySet,
			Now:    func() time.Time { return now },
		})
		require.Error(t, err)

		// With 2s tolerance, should pass
		_, err = Verify(token, VerifyConfig{
			KeySet:         keySet,
			ClockTolerance: 2 * time.Second,
			Now:            func() time.Time { return now },
		})
		require.NoError(t, err)
	})
}

func TestVerify_ClockTolerance_DefaultZero(t *testing.T) {
	priv, pub := testKey(t)
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*pub}}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Token with nbf 1s in the future - should fail with default (zero) tolerance
	claims := map[string]interface{}{
		"iss": "test-issuer",
		"sub": "test-subject",
		"aud": "test-audience",
		"exp": now.Add(1 * time.Hour).Unix(),
		"nbf": now.Add(1 * time.Second).Unix(),
	}

	token := signJWT(t, priv, claims)

	// Not specifying ClockTolerance should default to 0
	_, err := Verify(token, VerifyConfig{
		KeySet: keySet,
		Now:    func() time.Time { return now },
	})
	require.Error(t, err, "default ClockTolerance of 0 should not allow future nbf")
}

func TestVerify_ClockTolerance_NoNbfClaim(t *testing.T) {
	priv, pub := testKey(t)
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*pub}}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Token without nbf claim - should pass (nbf defaults to zero time, which is in the past)
	claims := map[string]interface{}{
		"iss": "test-issuer",
		"sub": "test-subject",
		"aud": "test-audience",
		"exp": now.Add(1 * time.Hour).Unix(),
		// Note: no "nbf" claim
	}

	token := signJWT(t, priv, claims)

	_, err := Verify(token, VerifyConfig{
		KeySet:         keySet,
		ClockTolerance: 2 * time.Second,
		Now:            func() time.Time { return now },
	})
	require.NoError(t, err, "token without nbf claim should pass")
}

func TestVerify_ClockTolerance_ErrorMessages(t *testing.T) {
	priv, pub := testKey(t)
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*pub}}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("expired token error includes tolerance info", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"exp": now.Add(-10 * time.Second).Unix(), // expired 10s ago
			"nbf": now.Add(-1 * time.Hour).Unix(),
		}

		token := signJWT(t, priv, claims)

		_, err := Verify(token, VerifyConfig{
			KeySet:         keySet,
			ClockTolerance: 2 * time.Second, // 2s tolerance isn't enough
			Now:            func() time.Time { return now },
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "2s tolerance", "error message should mention tolerance")
	})

	t.Run("nbf error includes tolerance info", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"exp": now.Add(1 * time.Hour).Unix(),
			"nbf": now.Add(10 * time.Second).Unix(), // 10s in future
		}

		token := signJWT(t, priv, claims)

		_, err := Verify(token, VerifyConfig{
			KeySet:         keySet,
			ClockTolerance: 2 * time.Second, // 2s tolerance isn't enough
			Now:            func() time.Time { return now },
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "2s tolerance", "error message should mention tolerance")
	})

	t.Run("error without tolerance does not mention tolerance", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "test-issuer",
			"sub": "test-subject",
			"aud": "test-audience",
			"exp": now.Add(-10 * time.Second).Unix(),
			"nbf": now.Add(-1 * time.Hour).Unix(),
		}

		token := signJWT(t, priv, claims)

		_, err := Verify(token, VerifyConfig{
			KeySet: keySet,
			// No ClockTolerance specified
			Now: func() time.Time { return now },
		})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "tolerance", "error message should not mention tolerance when none configured")
	})
}

func TestVerify_ClockTolerance_NegativeRejected(t *testing.T) {
	priv, pub := testKey(t)
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*pub}}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create a perfectly valid token
	claims := map[string]interface{}{
		"iss": "test-issuer",
		"sub": "test-subject",
		"aud": "test-audience",
		"exp": now.Add(1 * time.Hour).Unix(),
		"nbf": now.Add(-1 * time.Hour).Unix(),
	}

	token := signJWT(t, priv, claims)

	// Negative tolerance should be rejected
	_, err := Verify(token, VerifyConfig{
		KeySet:         keySet,
		ClockTolerance: -1 * time.Second,
		Now:            func() time.Time { return now },
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ClockTolerance must not be negative")

	verifyErr, ok := err.(*VerifyErr)
	require.True(t, ok, "expected VerifyErr")
	require.Equal(t, JWT_UNKNOWN, verifyErr.XJWTVerifyReason(), "negative tolerance should return JWT_UNKNOWN reason")
}
