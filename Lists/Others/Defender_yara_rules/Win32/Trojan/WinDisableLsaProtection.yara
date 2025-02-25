rule Trojan_Win32_WinDisableLsaProtection_A_2147934391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinDisableLsaProtection.A"
        threat_id = "2147934391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinDisableLsaProtection"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " add " wide //weight: 1
        $x_1_2 = "\\SYSTEM\\CurrentControlSet\\Control\\LSA " wide //weight: 1
        $x_1_3 = "/v RunAsPPL" wide //weight: 1
        $x_1_4 = "/t REG_DWORD" wide //weight: 1
        $x_1_5 = "/d 0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

