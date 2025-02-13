rule HackTool_Linux_SuspSudoAttemptCmd_A_2147767101_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspSudoAttemptCmd.A"
        threat_id = "2147767101"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspSudoAttemptCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell " wide //weight: 1
        $x_1_2 = "root" wide //weight: 1
        $x_1_3 = "machinectl " wide //weight: 1
        $x_1_4 = "--uid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

