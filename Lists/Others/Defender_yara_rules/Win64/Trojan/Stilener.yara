rule Trojan_Win64_Stilener_A_2147920401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stilener.A"
        threat_id = "2147920401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stilener"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6f 6c 61 6e 64 50 72 6f 6a 65 63 74 ?? 2f 73 69 6d 70 6c 65 50 72 6f 78 79 44 4c 4c 2f 6d 61 69 6e 2e 67 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 6f 78 79 2e 64 6c 6c 00 53 65 72 76 65 45 78 74 65 72 6e 61 6c ?? 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74}  //weight: 1, accuracy: Low
        $x_1_3 = {66 72 61 6d 65 2e 73 70 3d 3c 2d 2d ?? 25 76 20 25 2b 76}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 9c 24 88 03 00 ?? 48 89 c1 48 8b bc 24 80 00 00 00 31 f6 45 31 c0 4d 89 c1 48 8b 84 24 b8 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

