rule Trojan_Win32_Sathurbot_A_2147684094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sathurbot.A"
        threat_id = "2147684094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sathurbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 08 32 46 10 88 45 98 3c 3d 75 33 3b fb 75 2f 83 7d e8 10 8b 45 d4 73 03}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 c4 3c 00 00 00 c7 45 c8 40 ?? 00 00 e8 ?? ?? ?? ?? c7 45 d0 ?? ?? ?? ?? 84 c0 75 07 c7 45 d0 ?? ?? ?? ?? 8b 45 08 83 78 14 10}  //weight: 1, accuracy: Low
        $x_1_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 ?? ?? ?? ?? 72 65 67 73 76 72 33 32 2e 65 78 65 ?? ?? ?? ?? 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {22 25 73 22 2c 25 73 00 (2e 6f|2a 2e 78) 00}  //weight: 1, accuracy: Low
        $x_1_5 = {25 73 2d 25 73 2e 64 6c 6c 00 00 00 25 73 3a 25 64 00 00 00 74 6d 70 00 70 6c}  //weight: 1, accuracy: High
        $x_1_6 = "\\bot\\saturn" ascii //weight: 1
        $x_1_7 = {25 2e 38 78 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 6d 70 00 7c}  //weight: 1, accuracy: Low
        $x_1_8 = "HydraLoader.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sathurbot_B_2147684987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sathurbot.B"
        threat_id = "2147684987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sathurbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 38 3b 0f 84 98 00 00 00 8b 07 8b 08 49 3b f1 7c d7 e9 8a 00 00 00 3c 3c 75 0e ff 35}  //weight: 1, accuracy: High
        $x_1_2 = {5f 6d 6f 64 75 6c 65 2e 64 61 74 00 2a 2e 2a 00 44 61 74 61 5c}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 73 74 61 6c 6c 5f 6d 6f 64 75 6c 65 00 00 75 70 64 61 74 65 00 00 72 75 6e 5f 62 69 6e 61 72 79}  //weight: 1, accuracy: High
        $x_1_4 = {6f 70 65 6e 00 00 00 00 22 00 00 00 2c 44 6c 6c 49 6e 73 74 61 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = "\\bot\\saturn" ascii //weight: 1
        $x_1_6 = "HydraLoader.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

