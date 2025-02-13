rule HackTool_MacOS_SuspSuidChange_PA_2147932065_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSuidChange.PA"
        threat_id = "2147932065"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSuidChange"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 74 00 6f 00 75 00 63 00 68 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 73 00 62 00 2d 00 [0-96] 20 00 63 00 68 00 6d 00 6f 00 64 00 20 00 75 00 2b 00 73 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 73 00 62 00 2d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

