rule Trojan_Win64_Negetsog_UL_2147896570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Negetsog.UL!MTB"
        threat_id = "2147896570"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Negetsog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zver\\x64\\Release\\dll_network.pdb" ascii //weight: 1
        $x_1_2 = "cfccf3b06e07e1f2e6a317" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

