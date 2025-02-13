rule VirTool_Win64_Steauz_A_2147924965_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Steauz.A!MTB"
        threat_id = "2147924965"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Steauz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b 71 20 ba 86 45 6a ef 4c 89 f1 [0-19] 49 89 c5 48 b8 77 69 6e 69 6e 65 74 00 48 89 84 24 a0 00 00 00 ?? ?? ?? ba 4c 04 cb 8f 48 89 c6 48 89 c1 ?? ?? ?? ?? ?? 48 89 f1 ba 54 0d 04 71 48 89 c3 ?? ?? ?? ?? ?? 48 89 f1 ba 9c 10 13 02 49 89 c4 ?? ?? ?? ?? ?? 48 89 f1 ba 84 25 e9 37 48 89 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {41 54 55 57 48 89 d7 ba c8 cb da 7e 56 48 89 ce 4c 89 c1 53 4c 89 c3 48 83 ec 50 48 c7 44 24 40 00 00 00 00 48 c7 44 24 48 00 00 00 00 c7 44 24 3c 00 00 00 00 ?? ?? ?? ?? ?? ba 3c 09 e6 86 48 89 d9 48 89 c5 ?? ?? ?? ?? ?? ba 25 39 fa a1}  //weight: 1, accuracy: Low
        $x_1_3 = {55 31 c9 48 ba 35 2e 30 20 28 57 69 6e 48 89 e5 41 57 41 56 41 55 41 54 57 56 53 48 83 e4 f0 48 81 ec c0 01 00 00 48 89 84 24 50 01 00 00 48 b8 64 6f 77 73 20 4e 54 20 48 89 94 24 58 01 00 00 48 ba 36 2e 31 3b 20 57 4f 57 48 89 84 24 60 01 00 00 48 b8 36 34 29 20 41 70 70 6c 48 89 94 24 68 01 00 00 48 ba 65 57 65 62 4b 69 74 2f 48 89 84 24 70 01 00 00 48 b8 35 33 37 2e 33 36}  //weight: 1, accuracy: High
        $x_1_4 = {48 89 f1 ba 23 37 e6 94 48 89 44 24 68 ?? ?? ?? ?? ?? 48 89 f1 ba aa 40 17 0b 48 89 44 24 60 ?? ?? ?? ?? ?? 48 89 f1 ba f5 53 57 d0 48 89 44 24 70 ?? ?? ?? ?? ?? ba cb 3d 50 31 48 89 f1 48 89 44 24 78 [0-19] c7 84 24 99 00 00 00 6d 73 76 63 c7 84 24 9c 00 00 00 63 72 74 00 48 89 c6 ?? ?? ?? ba 4e 16 e5 08 49 89 c5 48 89 c1 ?? ?? ?? ?? ?? ba 52 2d 08 00 4c 89 e9 48 89 44 24 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

