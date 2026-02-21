rule SUSP_DotNet_Resource_Drop_Execute
{
    meta:
        description = "Suspicious .NET: resource extraction + console hiding + file drop + execute"
        author      = "frank"
        date        = "2026-02-21"
        score       = 60

    strings:
        $s1 = "GetManifestResourceStream" wide ascii fullword
        $s2 = "WriteAllBytes" wide ascii fullword
        $s3 = "ProcessStartInfo" wide ascii fullword
        $s4 = "ShowWindow" wide ascii fullword
        $s5 = "GetConsoleWindow" wide ascii fullword
        $s6 = "UseShellExecute" wide ascii fullword
        $s7 = "GetExecutingAssembly" wide ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        all of them
}
