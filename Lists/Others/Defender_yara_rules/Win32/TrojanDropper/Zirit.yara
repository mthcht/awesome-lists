rule TrojanDropper_Win32_Zirit_D_2147601430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zirit.D"
        threat_id = "2147601430"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {47 81 ff d0 07 00 00 7c c2 6a 00 e8 ?? ?? 00 00 8b 54 24 14 83 c4 04 2b c2 3d 60 54 00 00 89 44 24 10 73 79 6a 00 e8 ?? ?? 00 00 99 b9 14 00 00 00 83 c4 04 f7 f9 52 ff d5}  //weight: 4, accuracy: Low
        $x_4_2 = {50 68 02 00 00 80 ff d6 ba 00 97 49 01 8b 44 24 10 8d 04 80 8d 04 80 8d 0c 80 c1 e1 03 2b d1 52 ff d5}  //weight: 4, accuracy: High
        $x_2_3 = {61 6e 74 69 76 25 73 25 73 00 00 69 69 72 75 73}  //weight: 2, accuracy: High
        $x_2_4 = {4b 62 64 00 4d 6f 6e 00 57 69 6e 00 53 79 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zirit_D_2147601430_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zirit.D"
        threat_id = "2147601430"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0f 84 80 00 00 00 85 ff 76 18 83 ce ff 8d 43 01 2b f3 8a 0b 8a 10 32 d1 88 10 40 8d 14 06 3b d7 72 f0}  //weight: 8, accuracy: High
        $x_4_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 6a 04 8d 85 ?? ?? ?? ?? 6a 00 50 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 50 6a 00 6a 11 ff 15 ?? ?? ?? 00 85 c0 74 09 6a 00 50 ff 15 ?? ?? ?? 00 5f 5e 8b e5 5d c3}  //weight: 4, accuracy: Low
        $x_2_3 = "\\Installer\\{(null)}\\AvpRunOnce.dll" ascii //weight: 2
        $x_1_4 = ":Repeat" ascii //weight: 1
        $x_1_5 = "del \"%s\"" ascii //weight: 1
        $x_1_6 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_7 = "\\tempdel.bat" ascii //weight: 1
        $x_1_8 = "rundll32 \"%s\",service" ascii //weight: 1
        $x_1_9 = "%s\\%s.dll" ascii //weight: 1
        $x_1_10 = "AppEvents\\Schemes\\Apps\\Explorer\\Navigating" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zirit_K_2147602651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zirit.K"
        threat_id = "2147602651"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 5c c7 45 a4 00 00 00 00 c7 45 a8 00 00 00 00 c7 45 ac 00 00 00 00 c7 45 b0 00 00 00 00 c7 45 b4 00 00 00 00 c7 45 b8 00 00 00 00 c7 45 bc 00 00 00 00 c7 45 c0 00 00 00 00 c7 45 c4 00 00 00 00 c7 45 c8 00 00 00 00 c7 45 cc 00 00 00 00 c7 45 d0 00 00 00 00 c7 45 d4 00 00 00 00 c7 45 d8 00 00 00 00 c7 45 dc 00 00 00 00 c7 45 e0 00 00 00 00 c7 45 e4 00 00 00 00 c7 45 e8 00 00 00 00 c7 45 ec 00 00 00 00 c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 fc 00 00 00 00 60 68 00 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 30 00 00 50 6a 00 ff 15 ?? ?? ?? 10 89 45 f8 b8 00 00 00 00 83 e8 26 83 e8 04 6a 02 6a 00 50 ff 75 fc ff 15 ?? ?? ?? 10 6a 00 68 ?? ?? ?? 10 6a 04 68 ?? ?? ?? 10 ff 75 fc ff 15 ?? ?? ?? 10}  //weight: 1, accuracy: Low
        $x_1_3 = {81 6d c8 00 00 01 00 8b 45 ac 8b 40 50 05 00 01 00 00 81 45 c8 00 00 01 00 6a 40 68 00 30 00 00 50 ff 75 c8 ff 15 ?? ?? ?? 10 85 c0 74 d9}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 55 ac 83 c2 28 8b 02 03 45 a4 ff 75 10 ff 75 0c ff 75 08 ff d0 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

