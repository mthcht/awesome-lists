rule HackTool_MacOS_SuspFileCreation_P1_2147937945_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspFileCreation.P1"
        threat_id = "2147937945"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspFileCreation"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "chmod " wide //weight: 5
        $x_5_2 = "+s" wide //weight: 5
        $x_5_3 = "4777" wide //weight: 5
        $x_5_4 = "4755" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

