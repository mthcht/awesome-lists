rule Ransom_AndroidOS_SpySomware_A_2147764085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SpySomware.A!MTB"
        threat_id = "2147764085"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SpySomware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/lOcKeD FiLe?/locked.zip" ascii //weight: 1
        $x_1_2 = "Xgfgp2rGoN2PFc1YZ3z1DQ==" ascii //weight: 1
        $x_1_3 = "D7DA8C6FF33624E755CA928575D55582" ascii //weight: 1
        $x_1_4 = "_fuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

