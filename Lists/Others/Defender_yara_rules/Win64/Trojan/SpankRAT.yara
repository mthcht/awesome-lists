rule Trojan_Win64_SpankRAT_EM_2147967824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpankRAT.EM!MTB"
        threat_id = "2147967824"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpankRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\spank\\.cargo\\registry" ascii //weight: 2
        $x_1_2 = "schtasks/create/tnRmmAgentCore/tr/sconlogon/rlhighest/f" ascii //weight: 1
        $x_1_3 = "ProgramData\\RmmAgentCore" ascii //weight: 1
        $x_1_4 = "rmm_agent.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

