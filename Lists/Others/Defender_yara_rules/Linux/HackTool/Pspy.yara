rule HackTool_Linux_Pspy_A_2147910828_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Pspy.A!MTB"
        threat_id = "2147910828"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Pspy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dominicbreuker/pspy/internal/pspy" ascii //weight: 1
        $x_1_2 = "*pspy.Logger" ascii //weight: 1
        $x_1_3 = "*pspy.PSScanner" ascii //weight: 1
        $x_1_4 = "*pspy.FSWatcher" ascii //weight: 1
        $x_1_5 = "dominicbreuker/pspy/internal/config" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

