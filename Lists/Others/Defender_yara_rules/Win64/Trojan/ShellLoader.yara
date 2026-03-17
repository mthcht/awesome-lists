rule Trojan_Win64_ShellLoader_MPB_2147952661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellLoader.MPB!MTB"
        threat_id = "2147952661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {48 ff c0 48 89 85 ?? ?? ?? ?? 48 81 bd ?? ?? ?? ?? ?? ?? 00 00 73 5d 48 8b 85 ?? ?? ?? ?? 0f b6 44 05 10 89 85 ?? ?? ?? ?? 48 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 33 d2 48 8b 85 ?? ?? ?? ?? 48 8b 8d ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f be 84 05 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 33 c8 8b c1 48 8b 8d ?? ?? ?? ?? 88 84 0d ?? ?? ?? ?? eb 85 48 8d 0d ?? ?? ?? ?? ff 15}  //weight: 6, accuracy: Low
        $x_3_2 = "r3dt34m2025" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellLoader_GVB_2147959121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellLoader.GVB!MTB"
        threat_id = "2147959121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.SResume_Thread" ascii //weight: 2
        $x_1_2 = "main.SWrite_ProcessMemory" ascii //weight: 1
        $x_1_3 = "main.SVirtual_Alloc" ascii //weight: 1
        $x_1_4 = "main.GetRemotePeb" ascii //weight: 1
        $x_1_5 = "main.SatelliteOrbitCalculator" ascii //weight: 1
        $x_1_6 = "main.Is64Bit" ascii //weight: 1
        $x_1_7 = "main.Virtual_Alloc" ascii //weight: 1
        $x_1_8 = "main.Virtual_AllocEx" ascii //weight: 1
        $x_1_9 = "main.GetImageBase" ascii //weight: 1
        $x_1_10 = "main.AllocPEBuffer" ascii //weight: 1
        $x_1_11 = "main.Decode" ascii //weight: 1
        $x_1_12 = "main.Write_ProcessMemory" ascii //weight: 1
        $x_1_13 = "main.RedirectToPayload" ascii //weight: 1
        $x_1_14 = "main.GetRemotePebAddr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellLoader_MK_2147960196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellLoader.MK!MTB"
        threat_id = "2147960196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_35_1 = {41 b8 02 00 00 00 49 3b c0 4c 0f 42 c0 49 8b d6 48 83 3d ?? ?? ?? ?? 0f 48 0f 47 15 ?? ?? ?? ?? 48 03 d7 48 8d 4c 24 30}  //weight: 35, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellLoader_LM_2147962363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellLoader.LM!MTB"
        threat_id = "2147962363"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {80 f3 34 88 18 48 8d 40 01 0f b6 18 84 db}  //weight: 20, accuracy: High
        $x_10_2 = {90 b3 67 c7 45 97 67 5b 52 40 c7 45 9b 43 55 46 51 c7 45 9f 68 68 70 51 c7 45 a3 51 44 67 51 66 c7 45 a7 46 00 44 8b cf}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellLoader_SX_2147964803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellLoader.SX!MTB"
        threat_id = "2147964803"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {99 f7 fe 0f b6 cb 0f b6 44 15 d0 03 45 c8 03 c8 81 e1 ff 00 00 80 79}  //weight: 20, accuracy: High
        $x_10_2 = {8b 03 8d 5b 04 03 45 e8 8d 52 02 89 01 8d 49 08 66 8b 42 fe 46 66 89 41 fc 8b 47 18 3b f0 72 e0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellLoader_SXA_2147965023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellLoader.SXA!MTB"
        threat_id = "2147965023"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Shellcode Loader Started" ascii //weight: 10
        $x_10_2 = "schtasks /create /tn \"%s\" /tr \"\"%s\"\" /sc minute /mo 1 /st 00:00 /f" ascii //weight: 10
        $x_5_3 = "Shellcode execution completed" ascii //weight: 5
        $x_2_4 = "Downloading shellcode" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

