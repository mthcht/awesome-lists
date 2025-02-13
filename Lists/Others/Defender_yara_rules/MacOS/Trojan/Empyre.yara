rule Trojan_MacOS_Empyre_B_2147750318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Empyre.B!MTB"
        threat_id = "2147750318"
        type = "Trojan"
        platform = "MacOS: "
        family = "Empyre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BundledEmpyreLauncher/EmpyreStager/EmpyreStager/" ascii //weight: 3
        $x_1_2 = "_activateStager" ascii //weight: 1
        $x_1_3 = "Y21kID0gInBzIC1lZiB8IGdyZXAgTGl0dGxlXCBTbml0Y2ggfCBncmVwIC12IGdyZXAi" ascii //weight: 1
        $x_1_4 = "b3IgaSBpbiByYW5nZSgyNTYpOgogICAgaj0oaitTW2ldK29yZChrZXlbaSVsZW4oa2V5KV0pKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0K" ascii //weight: 1
        $x_1_5 = "CklWPWFbMDo0XTtkYXRhPWFbNDpdO2tleT1JVisnR144VkpFMSVlUFc9KEsvXWk1cWp5bHdGb30tclFBbjwnO1MsaixvdXQ9cmFuZ2UoMjU2KSwwLFtdCm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

