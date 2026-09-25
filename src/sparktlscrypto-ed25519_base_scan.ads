--  Internal constant-time scan, separate from the generated constants so
--  proof obligations do not expand the entire public table.
with SPARKTLSCrypto.Ed25519_Base_Table;
package SPARKTLSCrypto.Ed25519_Base_Scan with SPARK_Mode => On is
   function Select_Point
     (Table : Ed25519_Base_Table.Point_Row;
      K     : Ed25519_Base_Table.Nibble)
      return Ed25519_Base_Table.Cached_Point
     with Global => null;
end SPARKTLSCrypto.Ed25519_Base_Scan;
