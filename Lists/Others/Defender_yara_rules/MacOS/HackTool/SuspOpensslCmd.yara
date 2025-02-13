rule HackTool_MacOS_SuspOpensslCmd_A_2147809649_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspOpensslCmd.A!ReverseShell"
        threat_id = "2147809649"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspOpensslCmd"
        severity = "High"
        info = "ReverseShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "openssl" wide //weight: 10
        $x_30_2 = "s_client" wide //weight: 30
        $x_20_3 = "connect" wide //weight: 20
        $x_5_4 = "-quiet" wide //weight: 5
        $x_15_5 = "sh " wide //weight: 15
        $x_5_6 = "2>&1" wide //weight: 5
        $n_50_7 = "ssh" wide //weight: -50
        $n_50_8 = "-status" wide //weight: -50
        $n_50_9 = "-showcerts" wide //weight: -50
        $n_50_10 = "ossltest" wide //weight: -50
        $n_50_11 = "localhost" wide //weight: -50
        $n_50_12 = "127.0.0.1" wide //weight: -50
        $n_50_13 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

