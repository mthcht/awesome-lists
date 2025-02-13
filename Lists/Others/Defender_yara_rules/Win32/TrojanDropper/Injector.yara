rule TrojanDropper_Win32_Injector_A_2147610341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.A"
        threat_id = "2147610341"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WriteProcessMemory" ascii //weight: 10
        $x_10_2 = "CreateRemoteThread" ascii //weight: 10
        $x_10_3 = "%s\\decdel.bat" wide //weight: 10
        $x_10_4 = "\\windows\\system32\\winhelp32.exe" wide //weight: 10
        $x_10_5 = "\\windows\\system32\\drivers\\VIDEO.sys" wide //weight: 10
        $x_1_6 = {66 81 39 4d 5a 75 2b 8b 51 3c 85 d2 7c 24 81 fa 00 00 00 10 73 1c 8d 04 0a 89 45 e4 81 38 50 45 00 00 74}  //weight: 1, accuracy: High
        $x_1_7 = {5a eb 0c 03 ca 68 00 80 00 00 6a 00 57 ff 11 8b c6 5a 5e 5f 59 5b 5d ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Injector_D_2147636738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.D"
        threat_id = "2147636738"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 f8 01 1b db 43 84 db 74 ?? c7 ?? 07 00 01 00}  //weight: 3, accuracy: Low
        $x_1_2 = {8d 04 19 48 33 d2 f7 f1 f7 e9}  //weight: 1, accuracy: High
        $x_1_3 = {f6 c4 20 0f 85 ?? ?? 00 00 a8 02 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b f0 85 f6 74 0c 8b 04 24 50 55 ff d6 85 c0 0f 94 c3}  //weight: 1, accuracy: High
        $x_1_5 = "es\\Common Files\\ServetDown.exe" ascii //weight: 1
        $x_1_6 = "NDOWS\\SYSTEM32\\mstsc.exe" ascii //weight: 1
        $x_1_7 = {3a 38 30 38 30 2f 44 6f 77 [0-3] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Injector_F_2147637765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.F"
        threat_id = "2147637765"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 88 0f 47 40 d1 6d 08 ff 4d ?? eb}  //weight: 1, accuracy: Low
        $x_3_2 = {83 e9 0a c6 45 ?? e8 c6 45 ?? 6a ff 75 08 c6 45 ?? e8 89 ?? ?? ff 55}  //weight: 3, accuracy: Low
        $x_1_3 = "Internet Explorer\\ie.exe" ascii //weight: 1
        $x_1_4 = "RsingScan" ascii //weight: 1
        $x_1_5 = "-install \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Injector_G_2147637954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.G"
        threat_id = "2147637954"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 c7 85 ?? ?? ff ff 07 00 01 00 ?? b2 00 00 00}  //weight: 1, accuracy: Low
        $x_2_2 = {0b ce c1 e1 04 0b c8 8b c1 c1 e8 15 c1 e1 0b 0b c1}  //weight: 2, accuracy: High
        $x_1_3 = {8b 74 24 08 83 fe 07 73 12 6a}  //weight: 1, accuracy: High
        $x_1_4 = "KPlugin.Section" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Injector_H_2147638433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.H"
        threat_id = "2147638433"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 c7 84 24 ?? 00 00 00 02 00 01 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 73 3c 03 f3 81 3e 50 45 00 00 0f 85 ?? ?? 00 00 83 c6 04 89 74 24 28 83 ?? 14}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 28 33 ?? 83 ?? 28 45 66 8b 50 02 3b ?? 7e ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Injector_I_2147638750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.I"
        threat_id = "2147638750"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 0c 60 8b 4d ?? 03 c8 89 4d ?? 8b 45 ?? d1 e0 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {f7 75 14 8b 45 0c 0f b6 04 ?? 03 ?? 99 b9 00 ?? ?? 00 f7 f9 89 55}  //weight: 2, accuracy: Low
        $x_1_3 = {ff 6b c6 85 ?? ?? ff ff 43 c6 85 ?? ?? ff ff 5a c6 85 ?? ?? ff ff 56 c6 85 ?? ?? ff ff 47}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 70 50 8b 85 ?? ?? ff ff ff 70 34 ff 75 ?? ff 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Injector_A_2147735384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.A!MTB"
        threat_id = "2147735384"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BoxesPuzz.exe" wide //weight: 1
        $x_1_2 = "4231264597746134797546412536734219" wide //weight: 1
        $x_1_3 = ":\\Maz-milocevic4\\FlashGames.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Injector_AR_2147748551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Injector.AR!MSR"
        threat_id = "2147748551"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HexEnc.EXE" wide //weight: 1
        $x_1_2 = "HexEnc MFC Application" wide //weight: 1
        $x_1_3 = "MOfH?6M42F252loLt0N" ascii //weight: 1
        $x_1_4 = "7?COsSwyith8HYnnP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

