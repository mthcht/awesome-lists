rule Trojan_Win32_mofksys_2147982335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/mofksys!atmn"
        threat_id = "2147982335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "mofksys"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "schtasks" wide //weight: 5
        $x_10_2 = "c:\\windows\\resources\\svchost.exe" wide //weight: 10
        $x_7_3 = "/sc daily" wide //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

