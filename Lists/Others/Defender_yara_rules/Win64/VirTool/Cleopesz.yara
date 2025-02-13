rule VirTool_Win64_Cleopesz_A_2147919981_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cleopesz.A!MTB"
        threat_id = "2147919981"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cleopesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 50 48 8b 0d 19 ab 04 00 [0-24] 48 89 44 24 58 b8 ff ff ff ff 48 89 05 b6 aa 04 00 48 b8 07 00 00 00 01 00 00 00 48 89 05 ad aa 04 00 48 b8 5a 00 41 41 41 41 41 41 48 89 05 a4 aa 04 00 41 b9 04 00 00 00 41 b8 00 30 00 00 ba 00 00 01 00 48 8b 0d 7c aa 04 00 ?? ?? ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 f8 0f 00 00 33 d2 48 8b 0d 65 aa 04 00 ?? ?? ?? ?? ?? 48 8b 05 51 aa 04 00 48 8b 0d 12 aa 04 00 48 89 08 48 8b 05 48 aa 04 00 48 8b 0d 49 aa 04 00 48 89 08 c7 44 24 28 00 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 41 b8 03 00 00 00 ba 00 00 01 c0 48 8b 0d 99 a9 04 00 ?? ?? ?? ?? ?? ?? 48 89 05 54 a1 02 00 48 83 3d 4c a1 02 00 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 24 29 03 c6 44 24 2c a0 c6 44 24 2d 15 c6 44 24 30 70 c6 44 24 31 15 c6 44 24 34 08 c6 44 24 35 f0 c6 44 24 36 fd c6 44 24 37 c1 c6 44 24 20 30 c6 44 24 21 00 c6 44 24 38 00 c6 44 24 39 00 c6 44 24 3a 00 c6 44 24 3b 05 c6 44 24 44 58 c6 44 24 45 18 c6 44 24 40 88 c6 44 24 41 18 c6 44 24 3c 00 c6 44 24 3d 10 45 33 c0 ba e2 1b 00 00 48 8b 4c 24 70}  //weight: 1, accuracy: High
        $x_1_4 = {33 c0 83 f8 01 ?? ?? 48 8b 05 73 aa 02 00 48 89 44 24 78 [0-18] 8b 4c 24 30 ?? ?? ?? ?? ?? 48 63 4c 24 30 ?? ?? ?? ?? ?? ?? ?? 48 89 04 ca 48 63 44 24 30 ?? ?? ?? ?? ?? ?? ?? 45 33 c9 4c 8b 04 c1 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 0d 67 9e 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

