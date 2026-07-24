rule HackTool_Linux_SuspPasswdExfil_PA_2147973951_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPasswdExfil.PA"
        threat_id = "2147973951"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPasswdExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-4] 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00}  //weight: 10, accuracy: Low
        $x_5_2 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspPasswdExfil_PB_2147973952_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPasswdExfil.PB"
        threat_id = "2147973952"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPasswdExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-4] 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00}  //weight: 10, accuracy: Low
        $x_5_2 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspPasswdExfil_PC_2147973953_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPasswdExfil.PC"
        threat_id = "2147973953"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPasswdExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 00 61 00 72 00 20 00 [0-16] 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00}  //weight: 10, accuracy: Low
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

rule HackTool_Linux_SuspPasswdExfil_PE_2147974491_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPasswdExfil.PE"
        threat_id = "2147974491"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPasswdExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-48] 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00 [0-48] 7c 00 [0-4] 6e 00 63 00 20 00}  //weight: 10, accuracy: Low
        $x_10_2 = {63 00 61 00 74 00 20 00 [0-48] 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00 [0-48] 7c 00 [0-4] 74 00 65 00 6c 00 6e 00 65 00 74 00 20 00}  //weight: 10, accuracy: Low
        $n_50_3 = "127.0.0.1" wide //weight: -50
        $n_50_4 = "localhost" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule HackTool_Linux_SuspPasswdExfil_PF_2147974493_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPasswdExfil.PF"
        threat_id = "2147974493"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPasswdExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-48] 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00 [0-48] 7c 00 [0-4] 6f 00 70 00 65 00 6e 00 73 00 73 00 6c 00 20 00 73 00 5f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 [0-24] 2d 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

