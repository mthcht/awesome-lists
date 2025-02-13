rule HackTool_MacOS_SuspNetcatCmd_A_2147809642_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspNetcatCmd.A!BindShell"
        threat_id = "2147809642"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspNetcatCmd"
        severity = "High"
        info = "BindShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "mkfifo" wide //weight: 10
        $x_30_2 = {6e 00 63 00 20 00 [0-32] 2d 00 6c 00}  //weight: 30, accuracy: Low
        $x_10_3 = "sh " wide //weight: 10
        $n_50_4 = "localhost" wide //weight: -50
        $n_50_5 = "127.0.0.1" wide //weight: -50
        $n_50_6 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspNetcatCmd_A_2147809643_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspNetcatCmd.A!ReverseShell"
        threat_id = "2147809643"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspNetcatCmd"
        severity = "High"
        info = "ReverseShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "mkfifo" wide //weight: 10
        $x_20_2 = "nc " wide //weight: 20
        $x_10_3 = {2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_5_4 = "0<" wide //weight: 5
        $x_10_5 = "2>&1" wide //weight: 10
        $n_50_6 = "localhost" wide //weight: -50
        $n_50_7 = "127.0.0.1" wide //weight: -50
        $n_50_8 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_20_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

