rule HackTool_Linux_SuspFetchExecFallback_A_2147976942_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspFetchExecFallback.A"
        threat_id = "2147976942"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspFetchExecFallback"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 67 00 65 00 74 00 20 00 [0-255] 7c 00 [0-24] 73 00 68 00 [0-4] 7c 00 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-255] 7c 00 [0-24] 73 00 68 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 75 00 72 00 6c 00 20 00 [0-255] 7c 00 [0-24] 73 00 68 00 [0-4] 7c 00 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-255] 7c 00 [0-24] 73 00 68 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

