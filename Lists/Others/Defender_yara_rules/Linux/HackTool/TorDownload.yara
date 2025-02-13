rule HackTool_Linux_TorDownload_A_2147842707_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/TorDownload.A"
        threat_id = "2147842707"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "TorDownload"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "61"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "curl" wide //weight: 10
        $x_10_2 = "wget" wide //weight: 10
        $x_50_3 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 38 00 23 38 38 09 61 2d 7a 41 2d 5a 30 2d 39}  //weight: 50, accuracy: Low
        $x_1_4 = {73 00 6f 00 63 00 6b 00 73 00 23 01 01 02 34 35}  //weight: 1, accuracy: Low
        $x_1_5 = "usewithtor" wide //weight: 1
        $x_1_6 = "torsocks" wide //weight: 1
        $x_1_7 = "torify" wide //weight: 1
        $x_1_8 = "tor2web" wide //weight: 1
        $x_1_9 = "tor2socks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

