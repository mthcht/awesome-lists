rule HackTool_MacOS_SuspPythonCmd_A_2147809650_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspPythonCmd.A!ReverseShell"
        threat_id = "2147809650"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspPythonCmd"
        severity = "High"
        info = "ReverseShell: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "46"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 79 00 74 00 68 00 6f 00 6e 00 [0-32] 2d 00 63 00 [0-32] 69 00 6d 00 70 00 6f 00 72 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 63 00 61 00 6c 00 6c 00 [0-2] 28 00}  //weight: 10, accuracy: Low
        $x_10_3 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 70 00 6f 00 70 00 65 00 6e 00 [0-2] 28 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_15_5 = {6f 00 73 00 2e 00 73 00 65 00 74 00 75 00 69 00 64 00 [0-2] 28 00 [0-2] 30 00}  //weight: 15, accuracy: Low
        $x_5_6 = "af_inet" wide //weight: 5
        $x_5_7 = "sock_stream" wide //weight: 5
        $x_5_8 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-2] 28 00}  //weight: 5, accuracy: Low
        $x_1_9 = "dup2" wide //weight: 1
        $x_1_10 = "subprocess.pipe" wide //weight: 1
        $n_50_11 = "localhost" wide //weight: -50
        $n_50_12 = "127.0.0.1" wide //weight: -50
        $n_50_13 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_MacOS_SuspPythonCmd_A_2147809651_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspPythonCmd.A!ReverseShellSsl"
        threat_id = "2147809651"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspPythonCmd"
        severity = "High"
        info = "ReverseShellSsl: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "66"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 79 00 74 00 68 00 6f 00 6e 00 [0-32] 2d 00 63 00 [0-32] 69 00 6d 00 70 00 6f 00 72 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 63 00 61 00 6c 00 6c 00 [0-2] 28 00}  //weight: 10, accuracy: Low
        $x_10_3 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 70 00 6f 00 70 00 65 00 6e 00 [0-2] 28 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_10_5 = "shell=true" wide //weight: 10
        $x_15_6 = {6f 00 73 00 2e 00 73 00 65 00 74 00 75 00 69 00 64 00 [0-2] 28 00 [0-2] 30 00}  //weight: 15, accuracy: Low
        $x_5_7 = "af_inet" wide //weight: 5
        $x_5_8 = "sock_stream" wide //weight: 5
        $x_5_9 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-2] 28 00}  //weight: 5, accuracy: Low
        $x_20_10 = "wrap_socket" wide //weight: 20
        $x_1_11 = "dup2" wide //weight: 1
        $x_1_12 = "subprocess.pipe" wide //weight: 1
        $n_50_13 = "localhost" wide //weight: -50
        $n_50_14 = "127.0.0.1" wide //weight: -50
        $n_50_15 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_20_*) and 5 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

