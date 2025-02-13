rule Trojan_Win64_Shhload_A_2147850731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shhload.A"
        threat_id = "2147850731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shhload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 18 ?? ?? ?? 48 8d 55 e0 48 8d 4a 2c 48 89 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 28 ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 83 f8 01 0f 94 c0 84 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 28 ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 83 f8 01 0f 94 c0 84 c0 0f 84 3d 01 00 00 e9 17 01 00 00 48 8b 85 ?? ?? ?? ?? 48 8d 55 f0 48 8d 4a 2c 48 89 c2 e8 54 d5 01}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 28 ?? ?? ?? 48 89 c1 e8 16 de 01 00 83 f8 01 0f 94 c0 84 c0 0f 84 3d 01 00 00 e9 17 01 00 00 48 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 85 68 2f 00 00 48 89 c1 e8 ?? ?? ?? ?? 83 f8 01 0f 94 c0 84 c0}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 8b 05 32 c8 0e 00 ?? ?? ?? ?? 48 89 c2 b9 00 00 00 00 41 ff d0 48 8b 05 ec db 0e 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_7 = {41 54 55 57 56 53 48 81 ec ?? ?? ?? ?? b9 0d 00 00 00 31 c0 ?? ?? ?? ?? ?? 24 20 48 89 d7 f3 48 ab 48 8b 3d ?? ?? 0c 00 44 8b 0f 45 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

