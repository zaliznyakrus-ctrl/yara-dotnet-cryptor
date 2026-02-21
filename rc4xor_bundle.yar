import "pe"

rule RC4XOR_Crypter_Bundle
{
    meta:
        description = "Detects .NET Core single-file bundle containing RC4+XOR crypter dropper"
        author      = "frank"
        date        = "2026-02-21"
        score       = 85

    strings:
        // .NET Core bundle config markers
        $cfg1 = "\"p/1.0.0\"" ascii
        $cfg2 = "p.dll" ascii
        $cfg3 = ".NETCoreApp" ascii

        // P/Invoke: hide console window
        $api1 = "ShowWindow" ascii fullword
        $api2 = "GetConsoleWindow" ascii fullword

        // .NET resource extraction -> drop -> execute chain
        $api3 = "GetManifestResourceStream" ascii fullword
        $api4 = "WriteAllBytes" ascii fullword
        $api5 = "ProcessStartInfo" ascii fullword
        $api6 = "UseShellExecute" ascii fullword

        // Drop path (UTF-16LE .NET string literal)
        $drop = "C:\\Windows\\TEMP" wide

        // RC4 double-XOR PRGA in .NET IL bytecode:
        // xor (0x61) ... rem (mod 256) ... xor (0x61) -- modified RC4 signature
        $rc4_dxor = { 91 58 20 00 01 00 00 5D 91 61 ?? ?? ?? ?? ?? ?? 5D 91 61 }

    condition:
        uint16(0) == 0x5A4D and
        filesize > 10MB and filesize < 150MB and
        2 of ($cfg*) and
        $api1 and $api2 and
        3 of ($api*) and
        ($drop or $rc4_dxor)
}
