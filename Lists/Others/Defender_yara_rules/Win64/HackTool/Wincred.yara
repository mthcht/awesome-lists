rule HackTool_Win64_Wincred_I_2147740675_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Wincred.I"
        threat_id = "2147740675"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Wincred"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WCEAddNTLMCredentials" ascii //weight: 1
        $x_1_2 = "WCEDelNTLMCredentials" ascii //weight: 1
        $x_1_3 = "WCEGetNTLMCredentials" ascii //weight: 1
        $x_1_4 = "wceaux.dll" ascii //weight: 1
        $x_1_5 = {48 8b 84 24 f0 00 00 00 0f b7 40 4e 8b d0 48 8d 8c 24 20 05 00 00 ff 94 24 e8 00 00 00 48 8b 84 24 f0 00 00 00 0f b7 40 4e 48 8b 8c 24 40 0d 00 00 48 81 c1 18 08 00 00 44 8b c8 4c 8d 84 24 20 05 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 83 e0 3f 49 c1 e9 06 75 39 4d 8b c8 49 83 e0 07 49 c1 e9 03 74 11 66 66 66 90 90 48 89 11 48 83 c1 08 49 ff c9 75 f4}  //weight: 1, accuracy: High
        $x_1_7 = {48 8b 44 24 38 0f b7 00 99 2b c2 d1 f8 89 84 24 60 04 00 00 48 8b 44 24 38 48 8b 40 08 48 89 44 24 40 44 8b 8c 24 60 04 00 00 4c 8b 44 24 40 ba 00 04 00 00 48 8d 4c 24 60 e8 ?? ?? ?? ?? 89 44 24 48 83 7c 24 48 00 75 17 48 8b 84 24 80 04 00 00 c7 80 40 08 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule HackTool_Win64_Wincred_I_2147740678_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Wincred.I!!Wincred.gen!A"
        threat_id = "2147740678"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Wincred"
        severity = "High"
        info = "Wincred: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WCEAddNTLMCredentials" ascii //weight: 1
        $x_1_2 = "WCEDelNTLMCredentials" ascii //weight: 1
        $x_1_3 = "WCEGetNTLMCredentials" ascii //weight: 1
        $x_1_4 = "wceaux.dll" ascii //weight: 1
        $x_1_5 = {48 8b 84 24 f0 00 00 00 0f b7 40 4e 8b d0 48 8d 8c 24 20 05 00 00 ff 94 24 e8 00 00 00 48 8b 84 24 f0 00 00 00 0f b7 40 4e 48 8b 8c 24 40 0d 00 00 48 81 c1 18 08 00 00 44 8b c8 4c 8d 84 24 20 05 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 83 e0 3f 49 c1 e9 06 75 39 4d 8b c8 49 83 e0 07 49 c1 e9 03 74 11 66 66 66 90 90 48 89 11 48 83 c1 08 49 ff c9 75 f4}  //weight: 1, accuracy: High
        $x_1_7 = {48 8b 44 24 38 0f b7 00 99 2b c2 d1 f8 89 84 24 60 04 00 00 48 8b 44 24 38 48 8b 40 08 48 89 44 24 40 44 8b 8c 24 60 04 00 00 4c 8b 44 24 40 ba 00 04 00 00 48 8d 4c 24 60 e8 ?? ?? ?? ?? 89 44 24 48 83 7c 24 48 00 75 17 48 8b 84 24 80 04 00 00 c7 80 40 08 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

