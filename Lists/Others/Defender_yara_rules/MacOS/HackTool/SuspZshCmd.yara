rule HackTool_MacOS_SuspZshCmd_A_2147809646_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspZshCmd.A!BindShell"
        threat_id = "2147809646"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspZshCmd"
        severity = "High"
        info = "BindShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "70"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "zsh" wide //weight: 10
        $x_20_2 = "zmodload" wide //weight: 20
        $x_20_3 = "zsh/net/tcp" wide //weight: 20
        $x_20_4 = {7a 00 74 00 63 00 70 00 20 00 [0-32] 2d 00 6c 00}  //weight: 20, accuracy: Low
        $n_50_5 = "localhost" wide //weight: -50
        $n_50_6 = "127.0.0.1" wide //weight: -50
        $n_50_7 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspZshCmd_A_2147809647_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspZshCmd.A!ReverseShell"
        threat_id = "2147809647"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspZshCmd"
        severity = "High"
        info = "ReverseShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "zsh" wide //weight: 10
        $x_20_2 = "zmodload" wide //weight: 20
        $x_20_3 = "zsh/net/tcp" wide //weight: 20
        $x_20_4 = "ztcp" wide //weight: 20
        $x_10_5 = "zsh >&" wide //weight: 10
        $x_5_6 = "2>&" wide //weight: 5
        $x_5_7 = "0>&" wide //weight: 5
        $n_50_8 = "localhost" wide //weight: -50
        $n_50_9 = "127.0.0.1" wide //weight: -50
        $n_50_10 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

