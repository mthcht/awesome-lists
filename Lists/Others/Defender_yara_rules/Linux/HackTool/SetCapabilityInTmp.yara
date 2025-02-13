rule HackTool_Linux_SetCapabilityInTmp_A_2147889540_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SetCapabilityInTmp.A"
        threat_id = "2147889540"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SetCapabilityInTmp"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_22_1 = {73 00 65 00 74 00 63 00 61 00 70 00 20 00 63 00 61 00 70 00 5f 00 64 00 61 00 63 00 5f 00 6f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 2c 00 63 00 61 00 70 00 5f 00 73 00 79 00 73 00 5f 00 61 00 64 00 6d 00 69 00 6e 00 2c 00 63 00 61 00 70 00 5f 00 6d 00 61 00 63 00 5f 00 61 00 64 00 6d 00 69 00 6e 00 2b 00 65 00 [0-1] 70 00 20 00 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 22, accuracy: Low
        $x_22_2 = {73 00 65 00 74 00 63 00 61 00 70 00 20 00 63 00 61 00 70 00 5f 00 64 00 61 00 63 00 5f 00 6f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 2c 00 63 00 61 00 70 00 5f 00 73 00 79 00 73 00 5f 00 61 00 64 00 6d 00 69 00 6e 00 2c 00 63 00 61 00 70 00 5f 00 6d 00 61 00 63 00 5f 00 61 00 64 00 6d 00 69 00 6e 00 3d 00 65 00 [0-1] 70 00 20 00 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 22, accuracy: Low
        $x_22_3 = {73 00 65 00 74 00 63 00 61 00 70 00 20 00 63 00 61 00 70 00 5f 00 64 00 61 00 63 00 5f 00 6f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 2c 00 63 00 61 00 70 00 5f 00 73 00 79 00 73 00 5f 00 61 00 64 00 6d 00 69 00 6e 00 2b 00 65 00 [0-1] 70 00 20 00 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 22, accuracy: Low
        $x_22_4 = {73 00 65 00 74 00 63 00 61 00 70 00 20 00 63 00 61 00 70 00 5f 00 64 00 61 00 63 00 5f 00 6f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 2c 00 63 00 61 00 70 00 5f 00 73 00 79 00 73 00 5f 00 61 00 64 00 6d 00 69 00 6e 00 3d 00 65 00 [0-1] 70 00 20 00 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 22, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Linux_SetCapabilityInTmp_C_2147890166_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SetCapabilityInTmp.C"
        threat_id = "2147890166"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SetCapabilityInTmp"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_22_1 = {73 00 65 00 74 00 63 00 61 00 70 00 20 00 63 00 61 00 70 00 5f 00 64 00 61 00 63 00 5f 00 6f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 2b 00 65 00 [0-1] 70 00 20 00 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 22, accuracy: Low
        $x_22_2 = {73 00 65 00 74 00 63 00 61 00 70 00 20 00 63 00 61 00 70 00 5f 00 64 00 61 00 63 00 5f 00 6f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 3d 00 65 00 [0-1] 70 00 20 00 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 22, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

