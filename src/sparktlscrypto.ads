--  SPARKTLSCrypto root package — empty parent for the crypto primitives.
--  Concrete crypto lives in child packages: AES_GCM, P256, P384, X25519,
--  Ed25519, Fiat_25519, Fiat_P256, BigNat, RSA, HKDF, HKDF384, HMAC384,
--  Hashing.SHA256, MAC, Base64.
--
--  The Interfaces and SPARKNaCl context clauses here are inherited by
--  every child unit, mirroring the visibility children had under the
--  original SPARKTLS root.
with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;

package SPARKTLSCrypto with Pure is
end SPARKTLSCrypto;
