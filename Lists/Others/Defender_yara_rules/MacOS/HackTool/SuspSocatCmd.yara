rule HackTool_MacOS_SuspSocatCmd_A_2147809644_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSocatCmd.A!BindShell"
        threat_id = "2147809644"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSocatCmd"
        severity = "High"
        info = "BindShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "socat" wide //weight: 10
        $x_20_2 = "exec:" wide //weight: 20
        $x_5_3 = "bash" wide //weight: 5
        $x_5_4 = "pty" wide //weight: 5
        $x_1_5 = "tcp-listen:" wide //weight: 1
        $x_1_6 = "udp-listen:" wide //weight: 1
        $n_50_7 = "localhost" wide //weight: -50
        $n_50_8 = "127.0.0.1" wide //weight: -50
        $n_50_9 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_MacOS_SuspSocatCmd_A_2147809645_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSocatCmd.A!ReverseShell"
        threat_id = "2147809645"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSocatCmd"
        severity = "High"
        info = "ReverseShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "socat" wide //weight: 10
        $x_20_2 = "exec:" wide //weight: 20
        $x_5_3 = "bash" wide //weight: 5
        $x_5_4 = "pty" wide //weight: 5
        $x_1_5 = "tcp-connect:" wide //weight: 1
        $x_1_6 = "tcp4:" wide //weight: 1
        $x_1_7 = "udp-connect:" wide //weight: 1
        $x_1_8 = "udp4:" wide //weight: 1
        $n_50_9 = "localhost" wide //weight: -50
        $n_50_10 = "127.0.0.1" wide //weight: -50
        $n_50_11 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

