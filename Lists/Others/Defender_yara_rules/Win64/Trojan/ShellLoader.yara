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

