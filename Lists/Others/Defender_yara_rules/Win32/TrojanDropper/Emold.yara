rule TrojanDropper_Win32_Emold_E_2147618308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Emold.E"
        threat_id = "2147618308"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Emold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 0b c0 74 ?? 33 c0 64 8b 40 30 83 b8 b0 00 00 00 02 [0-6] 50 58 8b e4 6a 00 68 51 4f 68 57 54 b8 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Emold_E_2147618308_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Emold.E"
        threat_id = "2147618308"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Emold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 0b c0 74 [0-3] 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 59 e8 45 00 00 00 55 8b ec 52 8b 5d 10 8b 55 0c ff 72 08 8f 83 b8 00 00 00 8b 42 10 8b 4d 08 8b 09 8b 50 20 c1 c2 07 33 d1 89 50 20 01 50 24 31 48 24 89 83 b4 00 00 00 33 c0 89 43 04 89 43 08 89 43 0c 89 43 10 5a c9 c2 10 00 64 ff 30 64 89 20 9c 80 4c 24 01 01 0f 31 9d 33 c0 64 8f 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 b8 54 ca af 91 8b 75 14 ff d6 8b f8 eb 12 b9 ?? ?? ?? ?? f3 a4 5a 2b 55 14 89 45 14 03 d0 ff e2 e8 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Emold_G_2147619081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Emold.G"
        threat_id = "2147619081"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Emold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 8b 40 18 50 eb 0d 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 89 c3 e8 ?? ?? ?? ?? 89 c6 e8 ?? ?? ?? ?? 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 53 ff d6 54}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? 31 d2 31 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {30 07 2c 04 4f e2 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

