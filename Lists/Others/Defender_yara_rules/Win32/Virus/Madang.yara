rule Virus_Win32_Madang_A_2147630222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Madang.gen!A"
        threat_id = "2147630222"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Madang"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 8d 5f 2c 53 e8 ?? ff ff ff 3d 2e 65 78 65 74 0b 3d 2e 73 63 72 74 04 c9 c2 04 00 6a 64 ff 56}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 3f 50 45 0f 85 ?? 00 00 00 81 bf 9b 01 00 00 79 6c 50 7a 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {58 66 3d 60 e8 0f 84 ?? 00 00 00 81 4b 24 00 00 00 e0 6a 02 6a 00 ff 75 08 ff 56}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ec 00 10 00 00 c7 04 24 2a 2e 2a 00 8b c4 54 50 ff 56}  //weight: 1, accuracy: High
        $x_1_5 = "setupx" ascii //weight: 1
        $x_1_6 = "vguarder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Virus_Win32_Madang_B_2147689721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Madang.gen!B"
        threat_id = "2147689721"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Madang"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 78 03 79 01 eb e8}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 3e 4d 5a [0-6] eb 75 ee 0f b7 7e 3c 03 fe 8b 6f 78 03 ee 8b 5d 20}  //weight: 1, accuracy: Low
        $x_1_3 = "Angry Angel v" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

