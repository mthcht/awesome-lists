rule HackTool_Linux_SuspShadowExfil_PA_2147973948_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PA"
        threat_id = "2147973948"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-4] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00}  //weight: 10, accuracy: Low
        $x_5_2 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspShadowExfil_PB_2147973949_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PB"
        threat_id = "2147973949"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-4] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00}  //weight: 10, accuracy: Low
        $x_5_2 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspShadowExfil_PC_2147973950_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PC"
        threat_id = "2147973950"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 00 61 00 72 00 20 00 [0-16] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00}  //weight: 10, accuracy: Low
        $x_5_2 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_4 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_5 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspShadowExfil_PD_2147974320_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PD"
        threat_id = "2147974320"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-48] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00 [0-48] 7c 00 20 00 63 00 75 00 72 00 6c 00 20 00 [0-32] 40 00 2d 00 20 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {63 00 61 00 74 00 20 00 [0-48] 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00 [0-48] 7c 00 20 00 63 00 75 00 72 00 6c 00 20 00 [0-32] 40 00 2d 00 20 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Linux_SuspShadowExfil_PE_2147974490_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PE"
        threat_id = "2147974490"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-48] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00 [0-48] 7c 00 [0-4] 6e 00 63 00 20 00}  //weight: 10, accuracy: Low
        $x_10_2 = {63 00 61 00 74 00 20 00 [0-48] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00 [0-48] 7c 00 [0-4] 74 00 65 00 6c 00 6e 00 65 00 74 00 20 00}  //weight: 10, accuracy: Low
        $n_50_3 = "127.0.0.1" wide //weight: -50
        $n_50_4 = "localhost" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

