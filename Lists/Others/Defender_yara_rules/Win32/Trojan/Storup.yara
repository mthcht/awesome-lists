rule Trojan_Win32_Storup_B_2147658398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storup.B"
        threat_id = "2147658398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5b 0c 8b 5b 14 8b 1b 8b 1b 8b 5b 10 8b c3 8b d8 8b 73 3c 8b 74 1e 78 03 f3 8b 7e 20 03 fb 8b 4e 14}  //weight: 1, accuracy: High
        $x_1_2 = {2d f8 06 00 00 50 ff 75 f8 ff 57 f8 b9 ff 01 00 00 57 33 c0 8d bd f1 f7 ff ff c6 85 f0 f7 ff ff 00 f3 ab}  //weight: 1, accuracy: High
        $x_1_3 = {68 f8 06 00 00 51 ff 75 f8 ff 57 f0 ff 75 f8 ff 57 e8 8d 95 f0 f7 ff ff ff d2 33 c0 ac 85 c0 75 f9}  //weight: 1, accuracy: High
        $x_1_4 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 78 78 78 2e 6a 70 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Storup_D_2147665215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storup.D"
        threat_id = "2147665215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "202"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 25 2b 72 37 34 40 00}  //weight: 100, accuracy: High
        $x_100_2 = {00 62 2d 79 34 2d 3d 00}  //weight: 100, accuracy: High
        $x_1_3 = {2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {80 00 f5 ff 45 fc 39 4d fc 72 e3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 00 2e ff 45 fc 39 4d fc 72 e3}  //weight: 1, accuracy: Low
        $x_1_5 = {74 04 80 04 ?? f5 40 3b c1 72 e6 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 04 ?? 2e 40 3b c1 72 e6}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 4d 0c 8a 14 08 80 c2 f5 eb 09 8b 4d 0c 8a 14 08 80 c2 2e 88 14 08 40 3b}  //weight: 1, accuracy: High
        $x_1_7 = {f5 eb 03 80 ?? 2e 88 ?? ?? 40 3b}  //weight: 1, accuracy: Low
        $x_1_8 = {74 06 80 04 ?? f5 eb 04 80 04 ?? 2e ?? 3b ?? 7c}  //weight: 1, accuracy: Low
        $x_1_9 = {2c 0b 8b 4d 0c 03 4d e4 88 01 eb 12 8b 55 0c 03 55 e4 8a 02 04 2e 8b 4d 0c 03 4d e4 88 01}  //weight: 1, accuracy: High
        $x_1_10 = {8a 08 80 c1 2e 8b 95 f4 fe ff ff 03 95 b4 f8 ff ff 88 0a eb a5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Storup_H_2147683426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storup.H"
        threat_id = "2147683426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 0c 07 8b 84 24 14 01 00 00 0f b6 44 04 10 03 c2 23 c6 8a 44 04 10 30 01 47 3b 7d 0c 7c 96}  //weight: 1, accuracy: High
        $x_1_2 = {b8 4d 5a 00 00 66 39 45 00 75 f1 56 8b 75 3c 03 f5 81 3e 50 45 00 00 74 07}  //weight: 1, accuracy: High
        $x_1_3 = {8b 06 8b 48 28 85 c9 74 18 8b 46 04 03 c1 74 11 6a ff 6a 01 6a 00 ff d0}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 00 00 2a 00 00 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 5c 00 69 00 65 00 66 00 72 00 61 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Storup_I_2147683494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storup.I"
        threat_id = "2147683494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 07 8b 84 24 14 01 00 00 0f b6 44 04 10 03 c2 23 c6 8a 44 04 10 30 01 47 3b 7d 0c (72|7c) 96}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 4d 5a 00 00 66 39 45 00 75 f1 56 8b 75 3c 03 f5 81 3e 50 45 00 00 74 07}  //weight: 1, accuracy: High
        $x_1_3 = {8b 06 8b 48 28 85 c9 74 18 8b 46 04 03 c1 74 11 6a ff 6a 01 6a 00 ff d0}  //weight: 1, accuracy: High
        $x_1_4 = {00 2e 00 64 00 61 00 74 00 00 40 00 [0-32] (00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2e 00 64 00 6c 00 6c|00 5c 00 69 00 65 00 66 00 72 00 61 00 6d 00 65 00 2e 00 64 00 6c 00 6c)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

