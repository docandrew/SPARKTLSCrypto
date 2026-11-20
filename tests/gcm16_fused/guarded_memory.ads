--  Test-only memory between PROT_NONE guard pages, so a read or a write
--  one byte outside a buffer faults (SIGSEGV) instead of passing silently
--  as guard bytes would for reads. Allocate maps Size bytes (rounded up to
--  whole pages) with an inaccessible page on each side; At_End places a
--  Len-byte buffer so it ends exactly at the trailing guard page, and
--  At_Start places it at the first byte after the leading one.
with System;                  use System;
with System.Storage_Elements; use System.Storage_Elements;

package Guarded_Memory is
   type Region is private;
   function Allocate (Size : Storage_Offset) return Region;
   function At_End (R : Region; Len : Storage_Offset) return Address;
   function At_Start (R : Region) return Address;
private
   type Region is record
      Base : Address;          --  first accessible byte
      Data : Storage_Offset;   --  accessible bytes (whole pages)
   end record;
end Guarded_Memory;
