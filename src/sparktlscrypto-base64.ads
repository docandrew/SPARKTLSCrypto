---------------------------------------------------------------------------
--  @summary
--  Base64 Encoding and Decoding Routines
--
--  @description
--  This package contains routines for encoding and decoding byte-oriented
--  messages to/from Base64 format.
---------------------------------------------------------------------------
package SPARKTLSCrypto.Base64
   with SPARK_Mode
is

   type Base64_String is new String
      with Dynamic_Predicate =>
         --  Require padding to make encoded length divisible by 4
         Base64_String'Length mod 4 = 0 and
         --  Only RFC 4648 allowed characters
         (for all I in Base64_String'Range =>
            Base64_String (I) in 'a'..'z' | 'A' .. 'Z' | 
                                 '0' .. '9' | '+' | '/' | '=') and
         --  Padding characters can only appear at the last 2 positions
         (for all I in Base64_String'Range =>
            (if Base64_String (I) = '=' then
               (I = Base64_String'Last or
                I = Base64_String'Last - 1))) and
         --  If the penultimate char is padding, then the last must be also
         (if Base64_String'Length > 2 and then
            Base64_String (Base64_String'Last - 1) = '=' then
            Base64_String (Base64_String'Last) = '=') and
         --  Only positive indices
         Base64_String'First = 1;

   ---------------------------------------------------------------------------
   -- Given an input string, determine whether it represents a valid Base64
   -- encoded message
   -- @param Input A String which may or may not be a Base64-encoded message
   -- @return True if Input is valid Base64, False otherwise
   ---------------------------------------------------------------------------
   function Validate (Input : String) return Boolean
      with Post =>
         Validate'Result =
         (((Input'Length mod 4 = 0) and
         (for all C of Input =>
            C in 'a'..'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '/' | '=') and
         (for all I in Input'Range =>
            (if Input (I) = '=' then
               (I = Input'Last or
                I = Input'Last - 1))) and
         (if Input'Length > 2 and then
            Input (Input'Last - 1) = '=' then
            Input (Input'Last) = '=') and
         (Input'First = 1)) or
         (Input'Length = 0));

   ---------------------------------------------------------------------------
   -- Length of the encoding of N bytes: four characters for every three
   -- bytes, rounded up to a multiple of four (padding included).
   ---------------------------------------------------------------------------
   function Encoded_Length (N : Natural) return Natural
      with Pre  => N <= Natural'Last / 4,
           Post => Encoded_Length'Result <= N * 4 / 3 + 3 and
                   (if N = 0 then Encoded_Length'Result = 0) and
                   (if N > 0 then Encoded_Length'Result >= 4) and
                   Encoded_Length'Result mod 4 = 0;

   ---------------------------------------------------------------------------
   -- Encode into a caller-supplied buffer. Output (1 .. Length) receives
   -- the Base64 text (RFC 4648 section 4, with padding); the rest of Output
   -- is 'A'. Buffer-based like Decode, so callers size storage explicitly.
   ---------------------------------------------------------------------------
   procedure Encode
     (Plain  : in     Byte_Seq;
      Output :    out String;
      Length :    out Natural)
      with Pre  => Plain'First = 0
                   and then Plain'Last < N32'Last
                   and then Plain'Length <= Natural'Last / 4
                   and then Output'First = 1
                   and then Output'Length >= Encoded_Length (Plain'Length),
           Post => Length = Encoded_Length (Plain'Length);

   ---------------------------------------------------------------------------
   -- Length of the decoding of Encoded: three bytes for every four
   -- characters, less the padding.
   ---------------------------------------------------------------------------
   function Decoded_Length (Encoded : Base64_String) return Natural
      with Post => Decoded_Length'Result <= (Encoded'Length / 4) * 3;

   ---------------------------------------------------------------------------
   -- Decode into a caller-supplied buffer. Output (0 .. Length - 1)
   -- receives the bytes; the rest of Output is zero.
   ---------------------------------------------------------------------------
   procedure Decode
     (Encoded : in     Base64_String;
      Output  :    out Byte_Seq;
      Length  :    out Natural)
      with Pre  => Output'First = 0
                   and then Output'Last < N32'Last
                   and then Output'Length >= Decoded_Length (Encoded),
           Post => Length = Decoded_Length (Encoded);

end SPARKTLSCrypto.Base64;
