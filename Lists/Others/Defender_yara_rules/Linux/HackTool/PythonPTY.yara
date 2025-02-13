rule HackTool_Linux_PythonPTY_A_2147794477_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PythonPTY.A"
        threat_id = "2147794477"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PythonPTY"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "import pty" wide //weight: 5
        $x_5_2 = "pty.spawn(" wide //weight: 5
        $x_1_3 = "/bin/bash" wide //weight: 1
        $x_1_4 = "/bin/dash" wide //weight: 1
        $x_1_5 = "/bin/sh" wide //weight: 1
        $x_1_6 = "/bin/zsh" wide //weight: 1
        $x_1_7 = "/bin/ksh93" wide //weight: 1
        $x_1_8 = "/bin/ksh" wide //weight: 1
        $x_1_9 = "/bin/tcsh" wide //weight: 1
        $n_10_10 = "ansys" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

