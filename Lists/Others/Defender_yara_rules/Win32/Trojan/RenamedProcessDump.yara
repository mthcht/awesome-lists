rule Trojan_Win32_RenamedProcessDump_A_2147981697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RenamedProcessDump.A"
        threat_id = "2147981697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RenamedProcessDump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dllhost.exe" wide //weight: 1
        $x_1_2 = "-accepteula" wide //weight: 1
        $x_1_3 = "-r" wide //weight: 1
        $x_1_4 = "-ma" wide //weight: 1
        $x_1_5 = "lsass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

