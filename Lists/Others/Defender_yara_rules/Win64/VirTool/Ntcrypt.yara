rule VirTool_Win64_Ntcrypt_A_2147929497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ntcrypt.A"
        threat_id = "2147929497"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ntcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 20 65 48 8b 04 25 30 00 00 00 49 8b f8 48 8b f2 48 8b e9 45 33 d2 4c 8b 48 60 49 8b 41}  //weight: 1, accuracy: High
        $x_1_2 = {28 49 8b 73 30 49 8b e3 41 5f 41 5e 5f c3 cc f0 ff 41 08 8b 41 08 c3 b8 01 40 00 80 c3 cc cc 4d 85 c0 75 06 b8 03 40 00 80 c3 4c 8b 49 10 49 8b 81 30 08 00 00 48 3b 02 75 0d 49 8b 81 38 08 00 00 48 3b 42 08 74 19 49 8b 81 f0 08 00 00 48 3b 02 75 17 49 8b 81 f8 08 00 00 48 3b 42 08 75 0a 49 89 08 f0 ff 41 08 33 c0 c3 49 83 20 00 b8 02 40 00 80 c3 cc cc cc 83 c8 ff f0 0f c1 41 08 ff c8 c3 cc 33 c0 c3 cc 48 89 5c 24 08}  //weight: 1, accuracy: High
        $x_1_3 = {83 ec 60 41 83 ca ff 45 33 c0 48 8b f1 44 38 02 74 19 41 83 f8 40 73 13 41 8a 04 10 42 88 44 04 20 41 ff c0 41 80 3c 10 00 75 e7 41 8d 40 fc 42 c6 44 04 20 00 80 7c 04 20 2e 74 2a 42 c6 44 04 20 2e 41 ff c0 42 c6 44 04 20 64 41 ff c0 42 c6 44 04 20 6c 41 ff c0 41 8d 40 01 42 c6 44 04 20 6c c6 44 04 20 00 65 48 8b 04 25 30 00 00 00 48 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

