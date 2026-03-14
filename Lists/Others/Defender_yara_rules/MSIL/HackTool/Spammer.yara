rule HackTool_MSIL_Spammer_AMTB_2147964797_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Spammer!AMTB"
        threat_id = "2147964797"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spammer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whSpam" ascii //weight: 1
        $x_1_2 = "LithiumShared" ascii //weight: 1
        $x_1_3 = "ran by lithium" ascii //weight: 1
        $x_1_4 = "Discord nuker by verlox & russian heavy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

