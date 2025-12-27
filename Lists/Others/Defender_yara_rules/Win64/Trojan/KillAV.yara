rule Trojan_Win64_KillAV_A_2147851753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.A!MTB"
        threat_id = "2147851753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\.\\PROCEXP152" ascii //weight: 2
        $x_2_2 = "Except in KillProcessHandles" ascii //weight: 2
        $x_2_3 = "DeviceIoControl to Driver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_B_2147851898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.B!MTB"
        threat_id = "2147851898"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Extracting the driver to %ws" wide //weight: 2
        $x_2_2 = "Could not load driver %s may be loaded" wide //weight: 2
        $x_2_3 = "NoConnectTo %s Device" wide //weight: 2
        $x_2_4 = "PROCEXP.SYS" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_RPX_2147895318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.RPX!MTB"
        threat_id = "2147895318"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 4c 24 08 56 57 48 81 ec 88 00 00 00 c6 44 24 68 00 48 8d 44 24 69 48 8b f8 33 c0 b9 09 00 00 00 f3 aa 48 8d 44 24 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_RPY_2147895319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.RPY!MTB"
        threat_id = "2147895319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c9 10 2b c1 35 74 23 30 02 8b c8 48 c1 e1 08 48 c1 e8 18 48 0b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_MKX_2147897033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.MKX!MTB"
        threat_id = "2147897033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 0f 44 dc 4c 89 f0 31 d2 49 f7 f2 49 89 d0 48 89 d9 48 d1 e9 49 0f af ca 48 89 d8 31 d2 48 f7 f1 48 d1 e8 48 0f af d8 48 89 da c4 c2 fb f6 c5 43 8a 0c 31 43 32 0c 03 48 c1 e8 ?? 30 c1 43 88 0c 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_DA_2147917260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.DA!MTB"
        threat_id = "2147917260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "AV_KILLER" ascii //weight: 50
        $x_1_2 = "sc.exe create" ascii //weight: 1
        $x_1_3 = "sc.exe start " ascii //weight: 1
        $x_1_4 = ".\\TrueSight" ascii //weight: 1
        $x_1_5 = "MsMpEng.exe" ascii //weight: 1
        $x_1_6 = "Driver file created" ascii //weight: 1
        $x_1_7 = "Successfully terminated process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_BSA_2147928706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.BSA!MTB"
        threat_id = "2147928706"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "RealBlindingEDR" ascii //weight: 20
        $x_5_2 = "Permanently delete AV/EDR" ascii //weight: 5
        $x_5_3 = "driver_path" ascii //weight: 5
        $x_5_4 = "RealBlindingEDR.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_KillAV_BSB_2147928762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.BSB!MTB"
        threat_id = "2147928762"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {45 33 c0 33 d2 e9 f2 fd ff ff cc cc e9 17 4d 00 00 ?? ?? ?? 48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41}  //weight: 20, accuracy: Low
        $x_5_2 = {89 05 a0 1b 02 00 e8 cb 4c 00 00 33 c9 48 89 05 9a 1b 02 00 e8 15 52}  //weight: 5, accuracy: High
        $x_5_3 = {c1 fa 06 4c 89 34 03 48 8b c5 83 e0 3f 48 8d 0c c0 49 8b 04 d0}  //weight: 5, accuracy: High
        $x_15_4 = "renamed, msmpeng.exe, nissrv.exe, and mpcmdrun.exe were all renamed" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_ARAX_2147955721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.ARAX!MTB"
        threat_id = "2147955721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\NSecSoftBYOVD.pdb" ascii //weight: 3
        $x_2_2 = "Unload Driver Failed, You may need to unload driver manually" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_SE_2147958205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.SE!MTB"
        threat_id = "2147958205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Resource extracted to C:\\ProgramData\\NSecKrnl.sys" ascii //weight: 1
        $x_1_2 = "WatchDogKiller-main\\x64\\Release\\NSecSoftBYOVDdll.pdb" ascii //weight: 1
        $x_1_3 = "RunProcessTermination" ascii //weight: 1
        $x_1_4 = "Drivers\\NSecKrnl\\NSecKrnl\\bin\\NSecKrnl64.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_CR_2147958656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.CR!MTB"
        threat_id = "2147958656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 3a 06 01 00 48 63 c8 49 8b c6 48 f7 e1 48 c1 ea 04 48 6b c2 34 48 2b c8 0f b6 84 29 78 51 04 00 88 84 2b d0 ec 04 00 48 ff c3 48 3b df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

