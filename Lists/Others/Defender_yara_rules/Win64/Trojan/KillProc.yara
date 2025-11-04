rule Trojan_Win64_KillProc_EB_2147836522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillProc.EB!MTB"
        threat_id = "2147836522"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 8b 44 24 18 45 8a 0c 08 66 44 8b 54 24 26 66 44 0b 54 24 26 66 44 89 54 24 26 44 88 4c 24 24 48 8b 0c 24 48 89 4c 24 28 4c 8b 5c 24 08 4c 03 5c 24 48}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillProc_GVA_2147938150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillProc.GVA!MTB"
        threat_id = "2147938150"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "main.avlist" ascii //weight: 3
        $x_1_2 = "main.isProcessRunning" ascii //weight: 1
        $x_1_3 = "main.LoadDriver" ascii //weight: 1
        $x_1_4 = "main.FindProcessByName" ascii //weight: 1
        $x_1_5 = "main.TerminateProcessByIOCTL" ascii //weight: 1
        $x_1_6 = "main.RegisterProcessByIOCTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillProc_SX_2147956642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillProc.SX!MTB"
        threat_id = "2147956642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8d 45 20 48 c7 45 20 ?? ?? ?? ?? 48 89 44 24 30 33 d2 c6 44 24 28 00 48 8b f9 c7 44 24 20 ?? ?? ?? ?? ff 15}  //weight: 20, accuracy: Low
        $x_10_2 = {48 89 5c 24 08 57 48 83 ec 20 48 8b da 48 8b f9 e8 17 00 00 00 48 8b d3 48 8b cf e8 60 c1 ff ff 48 8b 5c 24 30 48 83 c4 20 5f c3 cc 48 8b 05 cd}  //weight: 10, accuracy: High
        $x_1_3 = "\\Device\\BlueBrid" ascii //weight: 1
        $x_1_4 = "BlueBrid loaded" ascii //weight: 1
        $x_1_5 = "MyDriver1\\x64\\Release\\MyDriver1.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

