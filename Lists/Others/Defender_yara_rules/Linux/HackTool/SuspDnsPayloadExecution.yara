rule HackTool_Linux_SuspDnsPayloadExecution_PA_2147974487_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspDnsPayloadExecution.PA"
        threat_id = "2147974487"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspDnsPayloadExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 00 69 00 67 00 20 00 [0-32] 54 00 58 00 54 00 20 00 [0-80] 7c 00 [0-4] 62 00 61 00 73 00 65 00 36 00 34 00 [0-4] 2d 00 64 00 [0-16] 7c 00 [0-32] 73 00 68 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

