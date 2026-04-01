rule HackTool_Linux_Ddexec_FZ2_2147966059_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ddexec.FZ2"
        threat_id = "2147966059"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ddexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ddexec.sh" wide //weight: 1
        $x_1_2 = "DDexec.git" wide //weight: 1
        $x_1_3 = {67 00 69 00 74 00 68 00 75 00 62 00 [0-80] 2f 00 44 00 44 00 65 00 78 00 65 00 63 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

