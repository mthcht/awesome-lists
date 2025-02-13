rule Trojan_Win32_Doxiss_A_2147637877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doxiss.A"
        threat_id = "2147637877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doxiss"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 76 69 64 6f 72 20 44 69 6f 78 69 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 68 00 61 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 10 00 00 00 63 00 6f 00 70 00 79 00 20 00 2f 00 79 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

