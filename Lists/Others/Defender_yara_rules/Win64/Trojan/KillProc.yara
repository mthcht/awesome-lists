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

