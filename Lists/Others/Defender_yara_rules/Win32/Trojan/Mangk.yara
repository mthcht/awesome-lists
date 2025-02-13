rule Trojan_Win32_Mangk_A_2147631263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mangk.A"
        threat_id = "2147631263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mangk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4f 01 83 c7 01 84 c9 75 f6 8b c8 c1 e9 02 f3 a5 8b c8 6a 38 8d 44 24 10 83 e1 03 6a 00 50 f3 a4 e8}  //weight: 1, accuracy: High
        $x_1_2 = "I'm Mr.K!http://www." ascii //weight: 1
        $x_1_3 = {2d 20 4d 72 2e 4b 22 [0-5] 6b 6d 69 61 6f 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

