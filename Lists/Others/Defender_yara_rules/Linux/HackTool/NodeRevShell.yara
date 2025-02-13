rule HackTool_Linux_NodeRevShell_A_2147783071_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/NodeRevShell.A"
        threat_id = "2147783071"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "NodeRevShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "nodejs -e" wide //weight: 2
        $x_2_2 = "node -e" wide //weight: 2
        $x_1_3 = {72 00 65 00 71 00 75 00 69 00 72 00 65 00 [0-2] 28 00 [0-4] 63 00 68 00 69 00 6c 00 64 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-4] 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 65 00 71 00 75 00 69 00 72 00 65 00 [0-2] 28 00 [0-4] 6e 00 65 00 74 00 [0-4] 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = "stdout.pipe" wide //weight: 1
        $x_1_6 = "stderr.pipe" wide //weight: 1
        $x_2_7 = "createServer(" wide //weight: 2
        $x_2_8 = {2e 00 73 00 70 00 61 00 77 00 6e 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 2, accuracy: Low
        $x_2_9 = {2e 00 65 00 78 00 65 00 63 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_NodeRevShell_B_2147783072_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/NodeRevShell.B"
        threat_id = "2147783072"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "NodeRevShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "nodejs -e" wide //weight: 2
        $x_2_2 = "node -e" wide //weight: 2
        $x_2_3 = {63 00 68 00 69 00 6c 00 64 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 73 00 70 00 61 00 77 00 6e 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 2, accuracy: Low
        $x_2_4 = {63 00 68 00 69 00 6c 00 64 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 63 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 2, accuracy: Low
        $x_2_5 = "stdio: [0, 1, 2]" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

