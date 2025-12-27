rule HackTool_Linux_LinuxEnum_C_2147956842_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/LinuxEnum.C"
        threat_id = "2147956842"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "LinuxEnum"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 00 6c 00 69 00 6e 00 75 00 78 00 2d 00 73 00 6d 00 61 00 72 00 74 00 2d 00 65 00 6e 00 75 00 6d 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 [0-255] 2f 00 6c 00 73 00 65 00 2e 00 73 00 68 00}  //weight: 10, accuracy: Low
        $n_50_2 = "cat " wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

