--  SPARKTLS MAC — HMAC-SHA-256
--
--  Derived from SPARKNaCl.MAC (R. Chapman, MIT license).
--  Uses SPARKTLSCrypto.Hashing.SHA256 (SHA-NI accelerated) internally.

with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.MAC with
   SPARK_Mode => On
is
   procedure HMAC_SHA_256 (Output : out Hashing.SHA256.Digest;
                           M      : in  Byte_Seq;
                           K      : in  Byte_Seq)
   with Global => null,
        Relaxed_Initialization => Output,
        Pre    => M'First = 0 and
                  M'Last < N32'Last - 256 and
                  (if K'Length > 0 then K'First = 0) and
                  K'Last < N32'Last - 256,
        Post   => Output'Initialized;

end SPARKTLSCrypto.MAC;
