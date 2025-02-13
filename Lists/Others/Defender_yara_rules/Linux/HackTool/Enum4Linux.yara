rule HackTool_Linux_Enum4Linux_A_2147765226_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Enum4Linux.A"
        threat_id = "2147765226"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Enum4Linux"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "perl" wide //weight: 10
        $x_20_2 = "enum4linux" wide //weight: 20
        $x_1_3 = "-u" wide //weight: 1
        $x_1_4 = "-m" wide //weight: 1
        $x_1_5 = "-s" wide //weight: 1
        $x_1_6 = "-p" wide //weight: 1
        $x_1_7 = "-g" wide //weight: 1
        $x_1_8 = "-d" wide //weight: 1
        $x_1_9 = "-a" wide //weight: 1
        $x_1_10 = "-r" wide //weight: 1
        $x_1_11 = "-l" wide //weight: 1
        $x_1_12 = "-k" wide //weight: 1
        $x_1_13 = "-o" wide //weight: 1
        $x_1_14 = "-n" wide //weight: 1
        $x_1_15 = "-i" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 11 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

