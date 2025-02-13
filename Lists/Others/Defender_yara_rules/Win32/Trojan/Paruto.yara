rule Trojan_Win32_Paruto_A_2147686765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paruto.A"
        threat_id = "2147686765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paruto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 3f 33 d2 f7 f1 83 c6 02 3b f3 8a 92 84 39 02 10 88 94 34 4f 01 00 00 72 dd}  //weight: 1, accuracy: High
        $x_1_2 = {66 c1 c8 05 0b f9 86 fd 0a c3 c0 ce 0e 66 c1 fa 05 23 fb 47 8a c3 f9 7f e7 c1 d7 11 f9 66 f7 d9 c0 d5 1a 66 c1 db 0d f6 e3 66 c1 d0 1f 66 0b db 66 c1 d1 07 fd 7a 31 22 e4 fc 23 fd 66 c1 e0 12 c0 d3 15 66 69 cb 75 61 fe c1 3a d4 66 c1 e1 0d 73 29}  //weight: 1, accuracy: High
        $x_1_3 = {76 63 6c 2e 74 6d 70 00 68 74 74 70 3a 2f 2f 25 73 2f 25 73 2e 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 75 74 6f 52 65 63 6f 76 65 72 00 25 73 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 52 65 63 6f 76 65 72 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 62 63 64 65 66 68 69 72 73 74 75 76 77 78 7a 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 69 6e 64 65 78 25 32 2e 32 64 5f 25 64 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {49 65 50 6f 72 78 79 76 2e 64 6c 6c 00 49 65 50 72 61 6d 47 65 74 00 49 65 53 65 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {55 70 64 76 61 4d 64 00 55 70 64 76 61 4d 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Paruto_2147689770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paruto"
        threat_id = "2147689770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paruto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c2 8a 4c 14 ?? f6 ea 04 03 84 c9 74 0a 3a c8 74 06 32 c8 88 4c 14 ?? 42 81 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 50 ff ?? 81 fb 02 01 00 00 74 ?? 81 fd 02 01 00 00 74 ?? 81 ff 02 01 00 00 74 ?? a1 ?? ?? ?? ?? 5d 85 c0 74 ?? 6a ff 50 ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = {25 03 00 00 80 79 ?? 48 83 c8 fc 40 40 8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 04 80 c1 e0 04}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c9 ff 33 c0 f2 ae f7 d1 49 83 f9 40 0f 83 ?? ?? 00 00 85 d2 0f 8e ?? ?? 00 00 81 fa ff ff 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

