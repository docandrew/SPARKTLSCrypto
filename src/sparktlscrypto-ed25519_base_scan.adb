with Interfaces; use Interfaces;
package body SPARKTLSCrypto.Ed25519_Base_Scan with SPARK_Mode => On is
   use Ed25519_Base_Table;
   function Select_Point (Table : Point_Row; K : Nibble) return Affine_Point is
      Result : Affine_Point :=
        (X => (others => 0), Y => (0 => 1, others => 0), T => (others => 0));
   begin
      for J in Digit loop
         pragma Loop_Invariant
           (for all L in Coordinate'Range =>
              Result.X (L) <= Limb'Last and
              Result.Y (L) <= Limb'Last and
              Result.T (L) <= Limb'Last);
         declare
            Diff : Unsigned_64 := Unsigned_64 (J) xor K;
            Mask : Unsigned_64;
         begin
            Diff := Diff or Shift_Right (Diff, 32);
            Diff := Diff or Shift_Right (Diff, 16);
            Diff := Diff or Shift_Right (Diff, 8);
            Diff := Diff or Shift_Right (Diff, 4);
            Diff := Diff or Shift_Right (Diff, 2);
            Diff := Diff or Shift_Right (Diff, 1);
            Mask := -(1 - (Diff and 1));
            for L in 0 .. 4 loop
               Result.X (L) := Result.X (L) xor
                 (Mask and (Result.X (L) xor Table (J).X (L)));
               Result.Y (L) := Result.Y (L) xor
                 (Mask and (Result.Y (L) xor Table (J).Y (L)));
               Result.T (L) := Result.T (L) xor
                 (Mask and (Result.T (L) xor Table (J).T (L)));
            end loop;
         end;
      end loop;
      return Result;
   end Select_Point;
end SPARKTLSCrypto.Ed25519_Base_Scan;
