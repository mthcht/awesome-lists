rule Ransom_Win32_Macaw_ZZ_2147796965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Macaw.ZZ"
        threat_id = "2147796965"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Macaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8b 4c 24 04 56 8b f0 c1 e8 02 83 e6 03 85 c0 74 0f 57 8b 3a 89 39 83 c1 04 83 c2 04 48 75 f3 5f 85 f6 74 0d 8b c1 2b d1 8a 0c 02 88 08 40 4e 75 f7 8b 44 24 08 5e c2 04 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Macaw_RR_2147797030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Macaw.RR!MTB"
        threat_id = "2147797030"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Macaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 17 66 0f bc cb 8d bf 04 00 00 00 66 d3 f0 f5 f6 d4 8d ad ff ff ff ff 8b cf 0f ba e0 29 0f b6 4c 25 00 32 cb 80 c1 98 66 0f a3 d8 66 d3 c8 f8 d0 c9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 fe cd d2 d1 12 cf 8d b6 04 00 00 00 0f b6 4c 25 00 81 c5 01 00 00 00 32 cb 66 f7 c6 0a 7a f9 f6 d1 80 f1 db}  //weight: 1, accuracy: High
        $x_1_3 = {33 cc d2 ed 32 d8 89 14 04 c0 dd 99 66 1b ca 66 13 cd 8b 0e 3b df 8d b6 04 00 00 00 66 85 e5 33 cb d1 c1 0f c9 f7 d9 f7 d1 f5 66 81 ff bf 57}  //weight: 1, accuracy: High
        $x_1_4 = {52 81 ca 1f 0e f7 7d 51 52 8b 94 14 79 d0 00 82 c7 44 24 18 7c 1d 48 52 c0 b4 24 00 00 00 00 9d b9 5c 7a 43 65 51 f9 81 84 24 10 00 00 00 48 7e 0f 48 59 59 59 8d 64 24 08 9d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

