rule Trojan_Win64_GhostRAT_A_2147897903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRAT.A!MTB"
        threat_id = "2147897903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b c1 41 83 c3 ?? 48 c1 e8 ?? 48 ff c2 8a 04 28 41 88 02 48 8b c1 48 c1 e8}  //weight: 2, accuracy: Low
        $x_2_2 = "%s\\shell\\open\\command" ascii //weight: 2
        $x_2_3 = "%-24s %-15s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GhostRAT_ARA_2147946569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRAT.ARA!MTB"
        threat_id = "2147946569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Release\\Code_Shellcode.pdb" ascii //weight: 2
        $x_2_2 = "VFPower" ascii //weight: 2
        $x_2_3 = "zhuxianlu" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

