with Interfaces.C; use Interfaces.C;

package body Guarded_Memory is
   Page : constant := 4096;

   function Mmap (A : Address; Len : size_t; Prot, Flags, Fd : int;
                  Off : long) return Address
     with Import, Convention => C, External_Name => "mmap";
   function Mprotect (A : Address; Len : size_t; Prot : int) return int
     with Import, Convention => C, External_Name => "mprotect";

   Prot_None       : constant int := 0;
   Prot_Read_Write : constant int := 3;
   Map_Private_Anonymous : constant int := 16#22#;

   function Allocate (Size : Storage_Offset) return Region is
      Data  : constant Storage_Offset :=
        Storage_Offset'Max (1, (Size + Page - 1) / Page) * Page;
      Total : constant Storage_Offset := Data + 2 * Page;
      A : constant Address :=
        Mmap (Null_Address, size_t (Total), Prot_Read_Write,
              Map_Private_Anonymous, -1, 0);
   begin
      if A = To_Address (Integer_Address'Last) then   --  MAP_FAILED
         raise Program_Error with "mmap failed";
      end if;
      if Mprotect (A, Page, Prot_None) /= 0
        or else Mprotect (A + Page + Data, Page, Prot_None) /= 0
      then
         raise Program_Error with "mprotect failed";
      end if;
      return (Base => A + Page, Data => Data);
   end Allocate;

   function At_End (R : Region; Len : Storage_Offset) return Address is
     (R.Base + R.Data - Len);

   function At_Start (R : Region) return Address is (R.Base);
end Guarded_Memory;
