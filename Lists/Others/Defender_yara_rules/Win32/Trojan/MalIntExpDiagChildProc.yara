rule Trojan_Win32_MalIntExpDiagChildProc_AA_2147957734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalIntExpDiagChildProc.AA"
        threat_id = "2147957734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalIntExpDiagChildProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ipconfig.exe" wide //weight: 1
        $x_1_2 = "netsh.exe" wide //weight: 1
        $x_1_3 = "route.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

