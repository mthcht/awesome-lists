rule Trojan_Win32_RecordBreaker_PA_2147830008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.PA!MTB"
        threat_id = "2147830008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c ?? 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 3, accuracy: Low
        $x_1_2 = "\\output.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_RF_2147834588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.RF!MTB"
        threat_id = "2147834588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c3 0f b6 f3 8a 54 34 ?? 02 fa 0f b6 cf 8a 44 0c ?? 88 44 34 ?? 88 54 0c ?? 0f b6 44 34 ?? 8b 4c 24 ?? 0f b6 d2 03 d0 0f b6 c2 8a 44 04 ?? 30 04 0f 47 3b 7c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_RDD_2147836067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.RDD!MTB"
        threat_id = "2147836067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d f8 c1 e9 18 33 4d fc}  //weight: 2, accuracy: High
        $x_2_2 = {03 ca 81 e1 ?? ?? ?? ?? 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_CM_2147839489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.CM!MTB"
        threat_id = "2147839489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {81 c7 d7 68 de 3a 8d 7f da 89 44 24 fc 83 ec 04 83 ec 04 89 34 24 83 ec 04 89 0c 24 89 44 24 fc 83 ec 04 60 8b 74 24 28 8b 7c 24 2c 8b 06 83 c6 04 89 44 24 1c 8b c8 c1 e9 02 83 e0 03 f3 a5}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_RDG_2147839953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.RDG!MTB"
        threat_id = "2147839953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChromeGrabber(): Sending %d files and %d txt files" wide //weight: 1
        $x_2_2 = {81 ef 04 00 00 00 66 33 d1 2b d6 85 e2 8b 17 f9 f8 f5 33 d3 c1 ca 02 66 3b c8 f8 81 f2 ?? ?? ?? ?? 4a f5 c1 ca 02 0f ca 66 3b e0 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_RDB_2147840144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.RDB!MTB"
        threat_id = "2147840144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Moldova" wide //weight: 1
        $x_1_2 = "kernel32.dll" ascii //weight: 1
        $x_1_3 = "timeGetTime" ascii //weight: 1
        $x_1_4 = "WDAGUtilityAccount" ascii //weight: 1
        $x_2_5 = {c6 45 b8 61 c6 45 b9 67 c6 45 ba 6a c6 45 bb 76 c6 45 bc 33 c6 45 bd 76 c6 45 be 33 c6 45 bf 6a c6 45}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_CP_2147840292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.CP!MTB"
        threat_id = "2147840292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SetDrv" ascii //weight: 1
        $x_1_2 = "SpecialBuild" ascii //weight: 1
        $x_1_3 = "7z SFX Constructor v4.6.0.0 (http://usbtor.ru/viewtopic.php?t=798)" ascii //weight: 1
        $x_1_4 = "5yw64ue5jyturyg" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "Thread32Next" ascii //weight: 1
        $x_1_7 = "OpenThread" ascii //weight: 1
        $x_1_8 = "SuspendThread" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_RecordBreaker_EH_2147843012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.EH!MTB"
        threat_id = "2147843012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {83 e2 1f 03 c2 c1 f8 05 6b c0 32 83 e0 42 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_RG_2147845246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.RG!MTB"
        threat_id = "2147845246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 67 66 66 66 89 c8 f7 ea c1 fa 02 89 c8 c1 f8 1f 29 c2 89 d0 05 96 00 00 00 29 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_RC_2147847388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.RC!MTB"
        threat_id = "2147847388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 41 85 f4 41 53 44 31 04 24 41 5b f9 4d 63 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_CCDS_2147895842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.CCDS!MTB"
        threat_id = "2147895842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 08 83 f2 ?? 88 14 08 31 c0 c7 04 24 ?? ?? ?? ?? c7 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_EM_2147900440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.EM!MTB"
        threat_id = "2147900440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 e8 80 03 f0 89 75 f8 8d 04 36 50 6a 40}  //weight: 2, accuracy: High
        $x_1_2 = "WTMR_" ascii //weight: 1
        $x_1_3 = "SMPHR_" ascii //weight: 1
        $x_1_4 = "wallets" ascii //weight: 1
        $x_1_5 = "wlts_" ascii //weight: 1
        $x_1_6 = "scrnsht_" ascii //weight: 1
        $x_1_7 = "Content-Type: application/x-object" ascii //weight: 1
        $x_1_8 = "autofill.txt" ascii //weight: 1
        $x_1_9 = "cookies.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RecordBreaker_ARA_2147925743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecordBreaker.ARA!MTB"
        threat_id = "2147925743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4f 08 8a 44 32 18 88 04 0a 42 3b 57 04 72 f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

