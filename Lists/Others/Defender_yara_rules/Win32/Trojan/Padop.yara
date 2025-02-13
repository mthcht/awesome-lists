rule Trojan_Win32_Padop_A_2147653739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Padop.A"
        threat_id = "2147653739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Padop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sendpopup=N19" wide //weight: 10
        $x_1_2 = "tracemyip.org/" wide //weight: 1
        $x_1_3 = "ws Restore\\num.txt" wide //weight: 1
        $x_1_4 = "attachment; name=\"uploaded\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

