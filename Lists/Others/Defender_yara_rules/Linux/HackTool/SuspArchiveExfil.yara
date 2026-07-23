rule HackTool_Linux_SuspArchiveExfil_PA_2147974321_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspArchiveExfil.PA"
        threat_id = "2147974321"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspArchiveExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 00 69 00 6e 00 64 00 20 00 [0-64] 2d 00 70 00 72 00 69 00 6e 00 74 00 30 00 [0-64] 7c 00 [0-4] 74 00 61 00 72 00 20 00 [0-64] 7c 00 [0-8] 6e 00 63 00}  //weight: 1, accuracy: Low
        $n_50_2 = "127.0.0.1" wide //weight: -50
        $n_50_3 = "localhost" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

