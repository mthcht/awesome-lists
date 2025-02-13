rule Trojan_Win32_Jurya_A_2147648312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jurya.A"
        threat_id = "2147648312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jurya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://223.244.225.3:" ascii //weight: 2
        $x_1_2 = "50/Installation.exe" ascii //weight: 1
        $x_1_3 = "single-ok-2" ascii //weight: 1
        $x_1_4 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_5 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "mailto:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

