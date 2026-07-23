rule HackTool_Linux_SuspEncPayloadExec_PA_2147974322_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspEncPayloadExec.PA"
        threat_id = "2147974322"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspEncPayloadExec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 00 70 00 65 00 6e 00 73 00 73 00 6c 00 20 00 65 00 6e 00 63 00 20 00 2d 00 64 00 [0-96] 7c 00 [0-4] 62 00 61 00 73 00 65 00 36 00 34 00 [0-4] 2d 00 64 00 [0-16] 7c 00 [0-32] 73 00 68 00}  //weight: 1, accuracy: Low
        $n_50_2 = "127.0.0.1" wide //weight: -50
        $n_50_3 = "localhost" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

