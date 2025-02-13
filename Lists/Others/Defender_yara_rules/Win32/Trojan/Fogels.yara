rule Trojan_Win32_Fogels_C_2147683238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fogels.C"
        threat_id = "2147683238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fogels"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 83 c1 01 89 4d 08 8b 55 08 0f be 02 85 c0 74 0f 8b 4d 08 8a 11 80 ea 01 8b 45 08 88 10 eb de}  //weight: 1, accuracy: High
        $x_1_2 = {8b 91 d4 01 00 00 ff d2 8b 85 ?? ?? ff ff 05 ?? 13 00 00 50 8d 8d ?? ?? ff ff 51 68}  //weight: 1, accuracy: Low
        $x_1_3 = {72 6d 2e 62 61 74 00 00 40 65 63 68 6f 20 6f 66 66 0d 0a 3a 6b 6c 0d 0a 65 72 61 73 65 20 22 25 73 22 20 3e 20 6e 75 6c}  //weight: 1, accuracy: High
        $x_1_4 = {6a 69 65 66 68 68 66 75 66 68 38 7a 6b 6c 6a f6 69 73 65 67 7a 67 7a 65 67 33 33 35 34 35 36 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

