rule Trojan_Win64_Cymuta_AH_2147816598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cymuta.AH!MTB"
        threat_id = "2147816598"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cymuta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "programdata\\Cymulate" ascii //weight: 3
        $x_3_2 = "attack_id" ascii //weight: 3
        $x_3_3 = "EDR_attacks_path" ascii //weight: 3
        $x_3_4 = "DummyService.pdb" ascii //weight: 3
        $x_3_5 = "temp\\CYM_EDR_SPREADED.txt" ascii //weight: 3
        $x_3_6 = "AttacksLogs" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

