rule Trojan_Win32_Nufsys_A_2147734002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nufsys.A!dha"
        threat_id = "2147734002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nufsys"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd /c echo|set/p=\"MZ\"" ascii //weight: 10
        $x_10_2 = "sysfun" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

