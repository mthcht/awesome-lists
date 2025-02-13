rule HackTool_MacOS_SuspSshCmd_A_2147809648_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSshCmd.A!ReverseShell"
        threat_id = "2147809648"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSshCmd"
        severity = "High"
        info = "ReverseShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "65"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ssh" wide //weight: 10
        $x_30_2 = "mkfifo" wide //weight: 30
        $x_20_3 = {2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 20, accuracy: Low
        $x_10_4 = "userknownhostsfile=/dev/null" wide //weight: 10
        $x_5_5 = "<0" wide //weight: 5
        $x_5_6 = "2>&1" wide //weight: 5
        $n_50_7 = "mklocale" wide //weight: -50
        $n_50_8 = "localhost" wide //weight: -50
        $n_50_9 = "127.0.0.1" wide //weight: -50
        $n_50_10 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

