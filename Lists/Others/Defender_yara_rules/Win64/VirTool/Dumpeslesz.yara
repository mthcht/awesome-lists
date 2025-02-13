rule VirTool_Win64_Dumpeslesz_A_2147913710_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dumpeslesz.A!MTB"
        threat_id = "2147913710"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumpeslesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 40 48 8b 8d 18 01 00 00 ?? ?? ?? ?? ?? ?? 48 89 85 58 01 00 00 c7 85 74 01 00 00 00 00 00 00 48 c7 44 24 20 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 44 8b 05 7e 9f 01 00 48 8b 15 6f 9f 01 00 48 8b 8d 58 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 89 45 3e c6 45 58 4d c6 45 59 69 c6 45 5a 6e c6 45 5b 69 c6 45 5c 44 c6 45 5d 75 c6 45 5e 6d c6 45 5f 70 c6 45 60 57 c6 45 61 72 c6 45 62 69 c6 45 63 74 c6 45 64 65 c6 45 65 44 c6 45 66 75 c6 45 67 6d c6 45 68 70 c6 45 69 00 [0-20] 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 4e 12 00 00 66 89 45 4e c6 45 50 93 c6 45 51 1b c6 45 52 d9 c6 45 53 cc c6 45 54 2e c6 45 55 ee c6 45 56 27 c6 45 57 e4 c7 45 74 00 00 00 00 ?? ?? ?? ?? 45 33 c0 33 d2}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 04 00 00 00 00 48 c7 45 28 00 00 00 00 [0-16] ba 08 00 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 83 7d 28 00 ?? ?? 48 8b 4d 28 ?? ?? ?? ?? ?? ?? 33 c0 ?? ?? ?? ?? ?? ?? 48 89 44 24 20 41 b9 04 00 00 00 ?? ?? ?? ?? ba 14 00 00 00 48 8b 4d 28}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 85 a8 01 00 00 48 ff c0 48 89 85 a8 01 00 00 [0-18] 48 39 85 a8 01 00 00 ?? ?? 48 8b 95 a8 01 00 00 [0-18] 48 8b 08 ?? ?? ?? ?? ?? ?? 48 89 85 b8 03 00 00 48 8b 95 a8 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

