rule HackTool_Linux_SuspSystemInfoExfil_PA_2147973801_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspSystemInfoExfil.PA"
        threat_id = "2147973801"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspSystemInfoExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 00 6e 00 61 00 6d 00 65 00 20 00 2d 00 [0-6] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {75 00 6e 00 61 00 6d 00 65 00 20 00 2d 00 [0-6] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

