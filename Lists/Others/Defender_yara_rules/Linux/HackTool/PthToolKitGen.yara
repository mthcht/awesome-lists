rule HackTool_Linux_PthToolKitGen_B_2147765357_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PthToolKitGen.B"
        threat_id = "2147765357"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PthToolKitGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2d 00 75 00 20 00 [0-128] 25 00 2e 20 20 00 3a 00}  //weight: 5, accuracy: Low
        $x_5_2 = {2d 00 2d 00 75 00 73 00 65 00 72 00 3d 00 [0-128] 25 00 2e 20 20 00 3a 00}  //weight: 5, accuracy: Low
        $x_10_3 = "//" wide //weight: 10
        $x_1_4 = "admin$" wide //weight: 1
        $x_1_5 = "c$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_PthToolKitGen_C_2147765358_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PthToolKitGen.C"
        threat_id = "2147765358"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PthToolKitGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "python" wide //weight: 10
        $x_50_2 = {2d 00 68 00 61 00 73 00 68 00 65 00 73 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 00}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_PthToolKitGen_E_2147765360_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PthToolKitGen.E"
        threat_id = "2147765360"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PthToolKitGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "python" wide //weight: 5
        $x_5_2 = "--lm=" wide //weight: 5
        $x_5_3 = "--nt=" wide //weight: 5
        $x_5_4 = "-t " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_PthToolKitGen_H_2147769871_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PthToolKitGen.H"
        threat_id = "2147769871"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PthToolKitGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "python" wide //weight: 10
        $x_50_2 = {2d 00 68 00 61 00 73 00 68 00 65 00 73 00 20 00 2f 40 40 00 3a 00}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

