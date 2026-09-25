with Interfaces; use Interfaces;
package body SPARKTLSCrypto.Ed25519_Base_Scan with SPARK_Mode => On is
   use Ed25519_Base_Table;
   function Select_Point (Table : Point_Row; K : Nibble) return Cached_Point is
      Result : Cached_Point :=
        (Y_Plus_X => (0 => 1, others => 0),
         Y_Minus_X => (0 => 1, others => 0), XY2D => (others => 0));
   begin
      for J in Digit loop
         pragma Loop_Invariant
           (for all L in Coordinate'Range =>
              Result.Y_Plus_X (L) <= Limb'Last and
              Result.Y_Minus_X (L) <= Limb'Last and
              Result.XY2D (L) <= Limb'Last);
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
               Result.Y_Plus_X (L) := Result.Y_Plus_X (L) xor
                 (Mask and (Result.Y_Plus_X (L) xor Table (J).Y_Plus_X (L)));
               Result.Y_Minus_X (L) := Result.Y_Minus_X (L) xor
                 (Mask and (Result.Y_Minus_X (L) xor Table (J).Y_Minus_X (L)));
               Result.XY2D (L) := Result.XY2D (L) xor
                 (Mask and (Result.XY2D (L) xor Table (J).XY2D (L)));
            end loop;
         end;
      end loop;
      return Result;
   end Select_Point;
end SPARKTLSCrypto.Ed25519_Base_Scan;
