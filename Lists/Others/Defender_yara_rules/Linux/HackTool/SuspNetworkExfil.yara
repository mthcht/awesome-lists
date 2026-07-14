rule HackTool_Linux_SuspNetworkExfil_PA_2147973617_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspNetworkExfil.PA"
        threat_id = "2147973617"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspNetworkExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 00 73 00 20 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {73 00 73 00 20 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

