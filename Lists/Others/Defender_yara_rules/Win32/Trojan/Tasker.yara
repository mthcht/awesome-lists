rule Trojan_Win32_Tasker_CB_2147805531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.CB!MTB"
        threat_id = "2147805531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 34 1a bf 80 d6 b3 38 59 66 8b c2 81 f1 ee 6a 67 66 bf 62 a5 a1 10 81 f1 8f 3b b1 3e 81 c1 1c 1e 36 11 be 6b d1 f4 3f 89 0c 13 66 b8 9d 2a 83 ea 04 66 bf 6a 0a 81 fa ac f5 ff ff 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b c6 e9}  //weight: 1, accuracy: High
        $x_2_3 = "atom.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_A_2147827693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.A!MTB"
        threat_id = "2147827693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 49 02 49 81 e9 06 00 00 00 49 63 d2 44 0f ab fa 66 44 0f ac f2 9f 66 41 d3 e0 0f b7 d7 49 0f bf d0 66 45 89 41 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_A_2147827693_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.A!MTB"
        threat_id = "2147827693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 81 ed 10 00 00 00 81 ed ?? ?? ?? ?? e9 [0-16] b8 ?? ?? ?? ?? 03 c5 81 c0 4c 00 00 00 b9 bc 05 00 00 ba 60 78 0a da 30 10 40 49}  //weight: 1, accuracy: Low
        $x_1_2 = "tg167AA750" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_BJ_2147828067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.BJ!MTB"
        threat_id = "2147828067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 0c 3d d2 2e 06 00 77 12 40 89 44 24 0c 3d f8 7c 29 34 0f 82}  //weight: 2, accuracy: High
        $x_2_2 = {33 c1 89 44 24 10 8b 54 24 10 89 54 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_GDA_2147838974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.GDA!MTB"
        threat_id = "2147838974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {32 4c 24 13 8b 4c 24 18 80 64 24 10 2e c6 44 24 10 4e 81 6c 24 10 65 55 a3 0d 31 74 24 10 c7 44 24 10 c0 79 43 59 33 74 24 10 23 74 24 10 0f 90 44 24 10 0f 9c 44 24 10 66 3b 74 24 11}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_HB_2147839490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.HB!MTB"
        threat_id = "2147839490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows File System Proxy" wide //weight: 1
        $x_1_2 = "SecureAnywhere needs to reboot your computer" ascii //weight: 1
        $x_1_3 = "kAkdnIlraigSb" ascii //weight: 1
        $x_1_4 = "keyloggers, screen-grabbers, clipboard stealers" ascii //weight: 1
        $x_1_5 = "Windows Firewall is currently disabled" ascii //weight: 1
        $x_1_6 = "Enable Enhanced Rootkit Detection" ascii //weight: 1
        $x_1_7 = "Disable Advanced Heuristics" ascii //weight: 1
        $x_1_8 = "CDebugger detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_GB_2147846991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.GB!MTB"
        threat_id = "2147846991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b7 d0 66 ff c8 81 fc c4 4d 28 21 66 87 d2 66 f7 d8 80 e6 31 66 81 da e9 3a 66 f7 d0 66 ff c2 3b c6 66 35 b8 1d 66 0f bd d3 66 05 12 3b 66 33 d8}  //weight: 2, accuracy: High
        $x_2_2 = {4e 91 90 3c a4 ba a0 5e 63 a2 3a cc 67 1a cd 85 86 c1 e0 7a 77 8e 33 28 c5 25 ce 78 d5 ba 3c eb}  //weight: 2, accuracy: High
        $x_1_3 = {e0 00 02 01 0b 01 0e 22 00 b4 02 00 00 a4 08 00 00 00 00 00 78 94 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_GNQ_2147851891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.GNQ!MTB"
        threat_id = "2147851891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 83 c0 ?? 89 45 fc 8b 4d fc 3b 4d 0c 7d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 55 fc 0f b6 02 83 f0 1e 8b 4d 08 03 4d fc 88 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_BAA_2147944119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.BAA!MTB"
        threat_id = "2147944119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a 2b d0 31 13 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tasker_LM_2147946818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tasker.LM!MTB"
        threat_id = "2147946818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {81 44 00 94 83 44 00 40 33 40 00 00 a8 44 00 94 30 40 00 b0 30 40 00 fc 83 44 00 40 75 43 00 6c 89 44 00 ac 6f 41 00 bc 85 44 00 f8 85 44 00 04 87 44 00 88 01 43 00 30 cb}  //weight: 20, accuracy: High
        $x_10_2 = {35 01 00 9c 96 42 00 8d 40 00 b8 1e 45 00 07 04 54 79 ?? 35 8c 1d 45 00 08 57 44 00 5e 00 05 55 6e 69 74 31 00 00 55 8b}  //weight: 10, accuracy: Low
        $x_5_3 = {33 c0 01 1e 8b 7d d8 03 7d a4 03 fb 03 f8 c7 45 b8 89 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d b8 81 ef 89 15 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

