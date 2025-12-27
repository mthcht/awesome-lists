rule Trojan_Win64_Ulise_NE_2147830317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.NE!MTB"
        threat_id = "2147830317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "@USVWATAUAVAWH" ascii //weight: 4
        $x_4_2 = "Px&FP0" ascii //weight: 4
        $x_3_3 = "trillian.exe" ascii //weight: 3
        $x_3_4 = "spawned.exe" ascii //weight: 3
        $x_1_5 = "GetTickCount64" ascii //weight: 1
        $x_1_6 = "OpenProcess" ascii //weight: 1
        $x_1_7 = "DefWindowProcA" ascii //weight: 1
        $x_1_8 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_AP_2147831293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.AP!MTB"
        threat_id = "2147831293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {f6 d2 32 54 04 30 41 32 d0 44 03 c7 41 88 11 4c 03 cf 45 3b c2 7c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_MA_2147840704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.MA!MTB"
        threat_id = "2147840704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {80 64 37 f8 f7 67 8d 4f 06 48 89 4e f8 31 c0 88 05 f7 2c 17 00 48 89 1e 48 89 46 18 c7 46 20 01 00 00 00 48 89 73 28 48 8d 46 30 0f b7 4b 02 48 8d 14 01 48 89 53 18 48 01 f7 48 29 cf}  //weight: 5, accuracy: High
        $x_2_2 = "great5" ascii //weight: 2
        $x_1_3 = "DllInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_DS_2147852095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.DS!MTB"
        threat_id = "2147852095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c2 49 f7 e1 49 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 05 0f be c0 6b c8 35 41 0f b6 c1 2a c1 04 31 42 30 44 0c 08 49 ff c1 49 83 f9 06 72}  //weight: 1, accuracy: High
        $x_1_2 = {71 58 40 71 5b 54 42 68 6e 0b 65 78 3c 00 00 00 71 58 40 51 5b 54 42 37 72 61 6d 63 5d 59 5a 56 4a 66 79 5a 4e 62 7d 3f 60 58 5e 5f 55 47 16 64 5d 5a 4f 49 55 49 47 1f 03 20 30 43 00 00 00 00 72 61 6d 75 5b 5a 52 68 6c 4b 4f 58 57 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_GMX_2147893318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.GMX!MTB"
        threat_id = "2147893318"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 63 04 24 48 8b 4c 24 28 0f be 04 01 89 44 24 04 8b 04 24 99 b9 3b 00 00 00 f7 f9 8b c2 83 c0 3a 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_A_2147906573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.A!MTB"
        threat_id = "2147906573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e6 4f d2 2a 26 48 28 6e 16 a3 ?? ?? ?? ?? ?? ?? ?? ?? 32 50 b9 30 55 d9 54 8a d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_AI_2147917654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.AI!MTB"
        threat_id = "2147917654"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b ca 41 f7 e3 80 c1 ?? 43 30 0c 02 c1 ea 03 8d 0c 92 03 c9 44 3b d9 4d 0f 44 cd 41 ff c3 49 ff c2 44 3b de 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {f7 e9 03 d1 c1 fa 08 8b c2 c1 e8 1f 03 d0 b8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_NS_2147923057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.NS!MTB"
        threat_id = "2147923057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 08 48 89 4a 18 48 8b 00 48 89 45 f8 48 83 f8 00 0f 84 ?? ?? ?? ?? 48 8b 45 f8 48 8b 4d d8 48 89 48 20 48 8b 45 d0}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8b 45 d0 48 8b 55 d8 48 83 c4 20 4c 8b 01 4c 89 45 e0 48 8b 49 08 48 89 4d e8 48 c7 42 20 00 00 00 00 48 05 68 08 00 00 49 c1 e0 08 4c 01 c0 48 c1 e1 03 48 01 c8}  //weight: 2, accuracy: High
        $x_1_3 = "RegQueryInfoKeyW" ascii //weight: 1
        $x_1_4 = "SleepConditionVariable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_AMCP_2147927577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.AMCP!MTB"
        threat_id = "2147927577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://176.111.174.140/bin/bot64.bin" ascii //weight: 10
        $x_3_2 = "ProcessHacker.exe" ascii //weight: 3
        $x_3_3 = "procexp64.exe" ascii //weight: 3
        $x_3_4 = "x64dbg.exe" ascii //weight: 3
        $x_3_5 = "autoruns.exe" ascii //weight: 3
        $x_1_6 = "Netflix Checker.exe" ascii //weight: 1
        $x_1_7 = "Application Data\\sysappec.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Ulise_ARAZ_2147928717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.ARAZ!MTB"
        threat_id = "2147928717"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 e9 55 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b d2 1a 2b ca 80 c1 61 41 88 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_AUL_2147941838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.AUL!MTB"
        threat_id = "2147941838"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 48 63 d0 48 8b 45 e0 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 e0 48 01 c8 83 f2 55 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_ARAX_2147956093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.ARAX!MTB"
        threat_id = "2147956093"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 89 c1 41 83 e1 07 47 8a 0c 0a 44 32 0c 01 44 88 0c 02 48 ff c0 41 39 c0 7f e5}  //weight: 2, accuracy: High
        $x_2_2 = {89 c8 99 41 f7 fa 48 63 d2 41 8a 04 13 32 04 0b 41 88 04 09 48 ff c1 41 39 c8 7f e4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Ulise_LM_2147957473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.LM!MTB"
        threat_id = "2147957473"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {40 00 00 40 6c 6c 76 6d 6d 73 76 63 00 e0 06 00 00 50 06 00 00 e0 06 00 00 cc 05 00}  //weight: 20, accuracy: High
        $x_10_2 = {c8 a3 30 00 8c 00 00 00 00 10 31 00 08 6d 01 00 00 e0 05 00 ec 34 00 00}  //weight: 10, accuracy: High
        $x_5_3 = {2e 66 70 74 61 62 6c 65 00 10 00 00 00 20 06}  //weight: 5, accuracy: High
        $x_2_4 = {90 74 20 00 30 00 00 00 a4 f9 30 00 40 01}  //weight: 2, accuracy: High
        $x_3_5 = {64 86 0c 00 5c b2 f0 68 00 00 00 00 00 00 00 00 f0 00 22 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_AHB_2147957980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.AHB!MTB"
        threat_id = "2147957980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {c6 85 8a 00 00 00 48 c6 85 8b 00 00 00 83 c6 85 8c 00 00 00 c4 c6 85 8d 00 00 00 28 c6 85 8e 00 00 00 c3}  //weight: 30, accuracy: High
        $x_20_2 = "Decrypting DLL with XOR key" ascii //weight: 20
        $x_10_3 = "[KeyGet] Reflective injection successful" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_AHC_2147958925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.AHC!MTB"
        threat_id = "2147958925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {42 8a 44 04 30 40 f6 c4 ?? 31 d0 42 88 04 01 66 44 0f ab f8 49 0f bf c3 e9 ?? ?? ?? ?? 69 c2 ?? ?? ?? ?? e9}  //weight: 30, accuracy: Low
        $x_20_2 = {66 41 0f be d0 d3 d2 89 c2 83 e2 ?? f5 f9 8a 14 11 f5 f7 c3 ?? ?? ?? ?? 30 14 03 e9}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ulise_AHC_2147958925_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ulise.AHC!MTB"
        threat_id = "2147958925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {31 d0 42 88 04 01 fe cc 41 8a c0 69 c2 ?? ?? ?? ?? 49 ff c0 2b d2 41 f7 f1 49 83 f8}  //weight: 30, accuracy: Low
        $x_20_2 = {42 8a 44 04 24 31 d0 42 88 04 01 69 c2 ?? ?? ?? ?? e9 ?? ?? ?? ?? 49 ff c0 f8 31 d2 f9 41 f7 f1 41 85 d1 49 81 fb ?? ?? ?? ?? e9}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

