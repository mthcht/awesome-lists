rule HackTool_Linux_SuspAuthKeyImplant_A_2147974494_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspAuthKeyImplant.A"
        threat_id = "2147974494"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspAuthKeyImplant"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 75 00 72 00 6c 00 20 00 [0-64] 7c 00 [0-4] 74 00 65 00 65 00 20 00 [0-32] 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00}  //weight: 10, accuracy: Low
        $x_10_2 = {77 00 67 00 65 00 74 00 20 00 [0-64] 7c 00 [0-4] 74 00 65 00 65 00 20 00 [0-32] 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

