rule Trojan_Win32_Vebzenpak_AE_2147752228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.AE!MTB"
        threat_id = "2147752228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 7e d2 81 [0-37] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e d2 [0-21] 0f ef d7 [0-21] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_GM_2147754835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.GM!MTB"
        threat_id = "2147754835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MKLWSemjEt8JmzlLtYgYdIgsvYrmTO8O0b4120" wide //weight: 1
        $x_1_2 = "KnkCgUGWmIfyUdBfQHFQZGG9huv8439qR2sX56e185" wide //weight: 1
        $x_1_3 = "FAf8mFJLsCmGuqvTekIKsxGfYbmCUvka9js131" wide //weight: 1
        $x_1_4 = "o6X9f6roA6HbOVYjQTdvLMNbIhAk1qaJBznsAl4x40" wide //weight: 1
        $x_1_5 = "u5g1fNqSZ1IsbUTwmpyorkvJdTmF6rw89hfnm24S99" wide //weight: 1
        $x_1_6 = "pxbLsjkhf3ZQesXC5ATfjV4naLrKOMRlD108" wide //weight: 1
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_B_2147755563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.B!MTB"
        threat_id = "2147755563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "afdelingssygeplejersker" wide //weight: 1
        $x_1_2 = "Transmitters" wide //weight: 1
        $x_1_3 = "Payability7" wide //weight: 1
        $x_1_4 = "Gyldighed6" wide //weight: 1
        $x_1_5 = "Nondistractive5" wide //weight: 1
        $x_1_6 = "innocence" wide //weight: 1
        $x_1_7 = "spdbarnet" wide //weight: 1
        $x_1_8 = "papered" wide //weight: 1
        $x_1_9 = "REDDERE" wide //weight: 1
        $x_1_10 = "Refineries7" wide //weight: 1
        $x_1_11 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_GG_2147756751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.GG!MTB"
        threat_id = "2147756751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0f 0f ee ca [0-48] 89 0c 24 [0-48] 02 ca 31 34 24 [0-32] 02 ca [0-64] 89 0c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_F_2147759960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.F!MTB"
        threat_id = "2147759960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YHVzmIAE9xP3QYjxLj9FMl7QdnjB4GZ4v9yLu8X88" wide //weight: 1
        $x_1_2 = "RyoLRaX6XG30YOsGwFAr0awDGAfS5naqEgWYCBoA239" wide //weight: 1
        $x_1_3 = "LYy9BXotghFaWf3r1teBHc3oNM0FOs192" wide //weight: 1
        $x_1_4 = "HUcPTuhgJIx1fauvVTilNmTRHEjVKWo6a8GSfU176" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_GV_2147760992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.GV!MTB"
        threat_id = "2147760992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1c 0a 50 [0-32] 81 f3 [0-48] f7 d7 [0-32] 89 1c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_C_2147762081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.C!MTB"
        threat_id = "2147762081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pb93PjP1aMa1lUZalQHKAjSICNViXNb3g191" wide //weight: 1
        $x_1_2 = "QmDx7cqA0IB9i6V0wlKar34" wide //weight: 1
        $x_1_3 = "Gs8LHszJHs" ascii //weight: 1
        $x_1_4 = "sBspKBs" ascii //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_KA_2147763501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.KA!MTB"
        threat_id = "2147763501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 1c 17 81 fb ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 31 f3 81 ff ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 01 1c 10 81 fa ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 83 c2 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_RT_2147782451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.RT!MTB"
        threat_id = "2147782451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEynwDgtMtaGCL5PDBeEFbBp1wKNEsG5RW641" ascii //weight: 1
        $x_1_2 = "genanvendelsesprocessernes" ascii //weight: 1
        $x_1_3 = "BREDBAANDSHJTTALER" ascii //weight: 1
        $x_1_4 = "SetArcDirection" ascii //weight: 1
        $x_1_5 = "GetLogicalDriveStringsA" ascii //weight: 1
        $x_1_6 = "IsSystemResumeAutomatic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_RF_2147786467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.RF!MTB"
        threat_id = "2147786467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Fuldblodsopdrtter" ascii //weight: 2
        $x_2_2 = "NvnFiqD6APHj1AzALW0ZG7XZp0gmGfCkUqMX185" ascii //weight: 2
        $x_1_3 = "definitionsjongleri" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_AF_2147787516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.AF!MTB"
        threat_id = "2147787516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DoFileDownload" ascii //weight: 3
        $x_3_2 = "PwdChangePasswordA" ascii //weight: 3
        $x_3_3 = "GetKeyboardLayoutNameA" ascii //weight: 3
        $x_3_4 = "Snittende" ascii //weight: 3
        $x_3_5 = "FtpGetCurrentDirectoryA" ascii //weight: 3
        $x_3_6 = "gethostbyname" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vebzenpak_ADF_2147896066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebzenpak.ADF!MTB"
        threat_id = "2147896066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebzenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {de 6f 84 00 c7 85 f8 ?? ?? ?? a0 87 7b 3c c7 85 fc ?? ?? ?? 06 5b 00 00 c7 85 48 ?? ?? ?? 54 b9 40 00 c7 85 40 ?? ?? ?? 08 00 00 00 8d 95 40 ?? ?? ?? 8d 8d 60 ?? ?? ?? e8 d6 40 ?? ?? 68 bc 13 00 00 8d 85 0c ?? ?? ?? 50 8d 85 50 ?? ?? ?? 50 dd 05 40 12 40 00 51 51 dd 1c 24 8d 85 10 ?? ?? ?? 50 68 95 f5 3a 00 8d 85 f8 ?? ?? ?? 50}  //weight: 10, accuracy: Low
        $x_5_2 = "TIPOFDAY.TXT" ascii //weight: 5
        $x_4_3 = "ROBUSTER" ascii //weight: 4
        $x_4_4 = "STARTPUNKTET" ascii //weight: 4
        $x_4_5 = "TALKWORTHY" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

