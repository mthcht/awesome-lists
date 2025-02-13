rule Trojan_Win32_Hinigto_A_2147652522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hinigto.A"
        threat_id = "2147652522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hinigto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 65 72 76 69 63 65 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 44 6f 77 6e 55 52 4c 25 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 45 78 65 46 69 6c 65 25 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 63 6d 64 20 2f 63 20 65 72 61 73 65 20 2f 46 20 22 00}  //weight: 1, accuracy: High
        $x_1_6 = {5a 58 85 ff 75 0c 85 d2 74 03 ff 4a f8 e8 ?? ?? ff ff 5a 5f 5e 5b 58 8d 24 94 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

