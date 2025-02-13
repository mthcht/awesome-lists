rule HackTool_Linux_WinExe_A_2147765163_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/WinExe.A"
        threat_id = "2147765163"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "WinExe"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "winexe" wide //weight: 20
        $x_5_2 = "-u" wide //weight: 5
        $x_1_3 = "//" wide //weight: 1
        $n_100_4 = "datahub" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

