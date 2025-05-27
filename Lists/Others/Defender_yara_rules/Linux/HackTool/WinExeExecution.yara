rule HackTool_Linux_WinExeExecution_BA_2147765788_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/WinExeExecution.BA"
        threat_id = "2147765788"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "WinExeExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "winexe" wide //weight: 5
        $x_2_2 = "//" wide //weight: 2
        $x_1_3 = "-u " wide //weight: 1
        $x_1_4 = "--user=" wide //weight: 1
        $x_1_5 = "--runas=" wide //weight: 1
        $x_1_6 = "-a " wide //weight: 1
        $x_1_7 = "--authentication-file=" wide //weight: 1
        $n_20_8 = "/airflow/" wide //weight: -20
        $n_20_9 = "winexe -U datahub%" wide //weight: -20
        $n_20_10 = "airflow task runner:" wide //weight: -20
        $n_20_11 = "SQLSERVER:\\SQLAS" wide //weight: -20
        $n_20_12 = "_JP1_" wide //weight: -20
        $n_20_13 = "/JP1/" wide //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

