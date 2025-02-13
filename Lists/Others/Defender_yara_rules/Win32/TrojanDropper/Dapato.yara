rule TrojanDropper_Win32_Dapato_M_2147721444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dapato.M!bit"
        threat_id = "2147721444"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7c 0f 01 00 48 8d 49 01 75 f5 0f b7 ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 66 89 04 39 4d 8b c1 49 ff c0 42 80 3c 02 00 75 f6 49 ff c0 0f 1f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 ff c0 42 80 3c 03 00 75 f6 49 83 c0 02 48 8d 4c 24 20 48 8b d3 e8 ?? ?? ?? ?? 33 d2 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 8b 8c 24 20 02 00 00 48 33 cc e8 ?? ?? ?? ?? 48 81 c4 30 02 00 00 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dapato_V_2147740886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dapato.V!MTB"
        threat_id = "2147740886"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 6a 08 c1 e2 ?? 59 f7 c2 00 00 00 80 74 ?? 03 d2 81 f2 b7 1d c1 04 eb ?? d1 e2 49 75 ?? 89 17 46 83 c7 ?? 81 fe 00 01 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "defender_delete" ascii //weight: 1
        $x_1_3 = "ServiceApp.exe" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dapato_BH_2147827944_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dapato.BH!MTB"
        threat_id = "2147827944"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 c1 8b 45 f8 8b 55 08 01 c2 8b 45 f8 89 4d f4 b9 20 00 00 00 89 55 f0 99 f7 f9 b8 00 20 40 00 01 d0 8b 4d f0 0f be 09 0f be 10 31 d1 8b 45 f4 88 08 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dapato_SV_2147888672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dapato.SV!MTB"
        threat_id = "2147888672"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 62 f6 e4 73 07 fa 7b 2e 13}  //weight: 2, accuracy: High
        $x_2_2 = {6d 77 fb fa 7f 09 cf 7b 36 7f 10 66 f5 44 e3 20 f6 21 30 18 ec}  //weight: 2, accuracy: High
        $x_2_3 = {56 4c c9 dc 36 41 ec 6e 2a 60 5a 28 aa 51 f9 17 b6 23 26 18 98 33 72 e7 e2 ec e9 19 a5 64 24 7f 60 3a 2d ea 93 e6 09 ae f0 61 14 0f 4d 40 4b 37}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dapato_GNX_2147903161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dapato.GNX!MTB"
        threat_id = "2147903161"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8wekyb3d8bbwe" ascii //weight: 1
        $x_1_2 = "KG4234B71yNR84293torkc34" ascii //weight: 1
        $x_1_3 = "/public/pages/Exodus.html" ascii //weight: 1
        $x_1_4 = "Atomic Wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

