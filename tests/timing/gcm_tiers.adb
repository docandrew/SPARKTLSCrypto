with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.GHASH_NI;
with SPARKTLSCrypto.AES_GCM_AVX2;
with SPARKTLSCrypto.AES_GCM_AVX512;

package body Gcm_Tiers is
   Have_AESNI  : constant Boolean := SPARKTLSCrypto.AES_NI.Has_AESNI;
   Have_PCLMUL : constant Boolean := SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ;
   Have_VAES2  : constant Boolean := SPARKTLSCrypto.AES_GCM_AVX2.Has_VAES_AVX2;
   Have_VAES5  : constant Boolean :=
     SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM;

   function Available (T : Tier) return Boolean is
     (case T is
         when Portable => True,
         when AES_NI_4 => Have_AESNI and Have_PCLMUL,
         when VAES_256 => Have_VAES2,
         when VAES_512 => Have_VAES5);

   procedure Select_Tier (T : Tier) is
   begin
      SPARKTLSCrypto.AES_NI.Has_AESNI := Have_AESNI and T /= Portable;
      SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ := Have_PCLMUL and T /= Portable;
      SPARKTLSCrypto.AES_GCM_AVX2.Has_VAES_AVX2 := Have_VAES2 and T = VAES_256;
      SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM :=
        Have_VAES5 and T = VAES_512;
   end Select_Tier;

   function Names return String is
     ("portable" &
      (if Available (AES_NI_4) then " aes-ni" else "") &
      (if Available (VAES_256) then " vaes-256" else "") &
      (if Available (VAES_512) then " vaes-512" else ""));
end Gcm_Tiers;
