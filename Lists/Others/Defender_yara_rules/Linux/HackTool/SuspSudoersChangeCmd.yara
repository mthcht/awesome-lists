rule HackTool_Linux_SuspSudoersChangeCmd_B_2147766655_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspSudoersChangeCmd.B"
        threat_id = "2147766655"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspSudoersChangeCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-u#-1" wide //weight: 10
        $x_1_2 = "sudo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_SuspSudoersChangeCmd_C_2147769227_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspSudoersChangeCmd.C"
        threat_id = "2147769227"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspSudoersChangeCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dd " wide //weight: 10
        $x_1_2 = "oflag=append" wide //weight: 1
        $x_1_3 = "of=/etc/sudoers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

