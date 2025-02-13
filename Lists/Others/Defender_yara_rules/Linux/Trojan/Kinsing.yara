rule Trojan_Linux_Kinsing_L_2147777323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kinsing.L"
        threat_id = "2147777323"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kinsing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "go-resty" ascii //weight: 1
        $x_1_2 = "gopsutil/cpu" ascii //weight: 1
        $x_1_3 = "diskv" ascii //weight: 1
        $x_2_4 = "main.getMinerPid" ascii //weight: 2
        $x_2_5 = "main.masscan" ascii //weight: 2
        $x_2_6 = "main.backconnect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

