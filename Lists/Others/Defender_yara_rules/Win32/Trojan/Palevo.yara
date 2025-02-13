rule Trojan_Win32_Palevo_MA_2147823656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Palevo.MA!MTB"
        threat_id = "2147823656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Palevo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 10 46 38 9e 13 00 8b 81 ?? ?? ?? ?? 8a 96 [0-15] 0f 44 f3 38 18 74 ?? 40 eb ?? 83 c1 04 83 f9 74 72}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f b6 d2 66 8b c1 66 0b c2 66 89 07 74 ?? 47 47 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Palevo_DJ_2147850190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Palevo.DJ!MTB"
        threat_id = "2147850190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Palevo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 06 03 45 fc f7 f1 8b 45 08 0f b6 1c 07 2b da 83 3d 30 88 40 00 00 0f 85 a7 00 00 00 85 db 7d 0f b8 ff 00 00 00 2b c3 c1 e8 08 c1 e0 08 03 d8 83 3d 34 88 40}  //weight: 1, accuracy: High
        $x_1_2 = {35 a8 87 40 00 ff 15 b0 70 40 00 be da 87 40 00 a1 40 88 40 00 3b 05 2c 88 40 00 7d 16 ff 35 38 87 40 00 68 4c 87 40 00 56 e8 15 51}  //weight: 1, accuracy: High
        $x_1_3 = {01 39 3d 40 88 40 00 74 13 ff 35 70 87 40 00 ff 35 84 87 40 00 e8 c9 4f 00 00 59 59 a1 34 88 40 00 3b 05 30 88 40 00 7e 2c 6a 20 68 8d}  //weight: 1, accuracy: High
        $x_1_4 = {eb e1 83 3d 34 88 40 00 00 74 0c e8 3e f7 ff ff 80 25 d7 87 40 00 00 8b 4b 38 8b 47 08 33 d2 f7 f1 40 0f af c1 03 e8 a1 68 87 40 00 a3 4c 87}  //weight: 1, accuracy: High
        $x_1_5 = {35 a8 87 40 00 ff d6 83 7d e4 02 75 20 81 ec 60 03 00 00 b9 d8 00 00 00 8d b5 e0 fa ff ff 8b fc f3 a5 e8 4a da ff ff 81 c4 60 03 00 00 83 7d e4 03 c6 05 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

