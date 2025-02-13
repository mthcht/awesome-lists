rule TrojanDropper_Win32_Evotob_A_2147691632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Evotob.A"
        threat_id = "2147691632"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Evotob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 10 00 00 74 ?? 3d 00 20 00 00 72 ?? 3d 00 30 00 00 73 ?? 43 eb ?? 3d 00 30 00 00 72 ?? 6a 02 eb ?? 3d 00 40 00 00 72 ?? 6a 03}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 65 40 40 ff 65 40 41 ff 65 40 42 ff 65 40 43 ff 65 40 46 ff 65 40 47 ff 65 40}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 46 1e 8d 44 30 20 50 68 04 01 00 00 ff 75 08 e8 ?? ?? ?? ?? 8b 46 0c 83 c4 0c 89 45 f4}  //weight: 1, accuracy: Low
        $x_1_4 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_5 = "RunYourMalwareHere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Evotob_A_2147692186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Evotob.gen!A"
        threat_id = "2147692186"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Evotob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 25 25 77 69 6e 64 69 72 25 25 5c 73 79 73 74 65 6d 33 32 5c 73 64 62 69 6e 73 74 2e 65 78 65 22 20 2f 71 20 2f 75 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Windows Defender\\Exclusions\\Processes  \" /v svchost.exe /t  REG_DWORD /d 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Evotob_B_2147693849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Evotob.B"
        threat_id = "2147693849"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Evotob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 10 00 00 74 ?? 3d 00 20 00 00 72 ?? 3d 00 30 00 00 73 ?? 43 eb ?? 3d 00 30 00 00 72 ?? 6a 02 eb ?? 3d 00 40 00 00 72 ?? 6a 03}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 65 40 40 ff 65 40 41 ff 65 40 42 ff 65 40 43 ff 65 40 46 ff 65 40 47 ff 65 40}  //weight: 1, accuracy: High
        $x_1_3 = {c1 fa 1f 33 d1 69 d2 65 89 07 6c 83 c0 04}  //weight: 1, accuracy: High
        $x_1_4 = {3e a3 03 00 00 00 3e c6 05 11 00 00 00 04 3e c7 05 5b 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Mazilla/5.0" ascii //weight: 1
        $x_1_6 = "Antimalware\\Exclusions\\Processes" ascii //weight: 1
        $x_1_7 = "RunYourMalwareHere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Evotob_B_2147694045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Evotob.gen!B!!Evotob.gen!B"
        threat_id = "2147694045"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Evotob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Evotob: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 10 00 00 74 ?? 3d 00 20 00 00 72 ?? 3d 00 30 00 00 73 ?? 43 eb ?? 3d 00 30 00 00 72 ?? 6a 02 eb ?? 3d 00 40 00 00 72 ?? 6a 03}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 65 40 40 ff 65 40 41 ff 65 40 42 ff 65 40 43 ff 65 40 46 ff 65 40 47 ff 65 40}  //weight: 1, accuracy: High
        $x_2_3 = {22 25 25 77 69 6e 64 69 72 25 25 5c 73 79 73 74 65 6d 33 32 5c 73 64 62 69 6e 73 74 2e 65 78 65 22 20 2f 71 20 2f 75 20 22 25 73 22 00}  //weight: 2, accuracy: High
        $x_1_4 = "Mazilla/5.0" ascii //weight: 1
        $x_1_5 = "Antimalware\\Exclusions\\Processes" ascii //weight: 1
        $x_1_6 = "RunYourMalwareHereWithHighIntegrityLevel" ascii //weight: 1
        $x_1_7 = ":Zone.Identifier" ascii //weight: 1
        $x_1_8 = "KB3000061" ascii //weight: 1
        $x_1_9 = "$$$Secure UAP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Evotob_C_2147694109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Evotob.C"
        threat_id = "2147694109"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Evotob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$$$Secure UAP" ascii //weight: 1
        $x_1_2 = "KB3000061" ascii //weight: 1
        $x_2_3 = {3d 00 10 00 00 74 ?? 3d 00 20 00 00 72 ?? 3d 00 30 00 00 73 ?? 43 eb ?? 3d 00 30 00 00 72 ?? 6a 02 eb ?? 3d 00 40 00 00 72 ?? 6a 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

