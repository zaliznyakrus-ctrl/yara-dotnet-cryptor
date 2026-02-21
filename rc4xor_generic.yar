rule RC4XOR_Crypter_Generic
{
    meta:
        description = "Generic .NET RC4+XOR resource decrypt-drop-execute pattern"
        author      = "frank"
        date        = "2026-02-21"
        score       = 80

    strings:
        // Console hiding P/Invoke combo
        $hide1 = "ShowWindow" wide ascii fullword
        $hide2 = "GetConsoleWindow" wide ascii fullword

        // .NET resource loading
        $res1 = "GetManifestResourceStream" wide ascii fullword
        $res2 = "GetExecutingAssembly" wide ascii fullword

        // File drop + process execution
        $exec1 = "WriteAllBytes" wide ascii fullword
        $exec2 = "ProcessStartInfo" wide ascii fullword
        $exec3 = "UseShellExecute" wide ascii fullword

        // Modified RC4 double-XOR in IL:
        //   load_array_elem, add, ldc.i4(256), rem, load_array_elem, xor, ..., xor
        $rc4_dxor = { 91 58 20 00 01 00 00 5D 91 61 ?? ?? ?? ?? ?? ?? 5D 91 61 }

        // KSA swap pattern in IL: ldelem, stelem, ldelem, stelem with mod 256
        $rc4_ksa = { 91 9C 06 ?? ?? ?? 9C ?? 17 58 }

    condition:
        uint16(0) == 0x5A4D and
        $hide1 and $hide2 and
        $res1 and $res2 and
        2 of ($exec*) and
        ($rc4_dxor or $rc4_ksa)
}
