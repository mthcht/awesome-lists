rule HackTool_MacOS_ShadowHashDataAccess_A_2147965504_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/ShadowHashDataAccess.A"
        threat_id = "2147965504"
        type = "HackTool"
        platform = "MacOS: "
        family = "ShadowHashDataAccess"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 00 73 00 63 00 6c 00 [0-32] 72 00 65 00 61 00 64 00 [0-80] 64 00 73 00 61 00 74 00 74 00 72 00 74 00 79 00 70 00 65 00 6e 00 61 00 74 00 69 00 76 00 65 00 3a 00 73 00 68 00 61 00 64 00 6f 00 77 00 68 00 61 00 73 00 68 00 64 00 61 00 74 00 61 00}  //weight: 10, accuracy: Low
        $n_100_2 = "-read /Users/panopto_upload" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

