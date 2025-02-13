rule Trojan_Win32_Fenibot_A_2147682008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fenibot.A"
        threat_id = "2147682008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fenibot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 21 62 6f 74 6b 69 6c 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 58 44 44 6f 53 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4e 6f 20 46 54 50 20 41 63 63 6f 75 6e 74 73 20 46 6f 75 6e 64 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

