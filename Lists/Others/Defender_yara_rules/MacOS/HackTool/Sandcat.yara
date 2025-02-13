rule HackTool_MacOS_Sandcat_A_2147894005_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Sandcat.A!MTB"
        threat_id = "2147894005"
        type = "HackTool"
        platform = "MacOS: "
        family = "Sandcat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sandcat.go" ascii //weight: 1
        $x_1_2 = "UpdateAgent" ascii //weight: 1
        $x_1_3 = "sending payload" ascii //weight: 1
        $x_1_4 = "clientkeyexchangemsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

