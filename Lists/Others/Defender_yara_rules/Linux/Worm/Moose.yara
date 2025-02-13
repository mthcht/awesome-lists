rule Worm_Linux_Moose_A_2147695478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Linux/Moose.gen!A"
        threat_id = "2147695478"
        type = "Worm"
        platform = "Linux: Linux platform"
        family = "Moose"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "echo -n -e \"H3lL0WoRlD\"" ascii //weight: 5
        $x_5_2 = "stratum+tcp://" ascii //weight: 5
        $x_3_3 = "/Challenge" ascii //weight: 3
        $x_5_4 = "/home/hik/start.sh" ascii //weight: 5
        $x_3_5 = "cat /proc/cpuinfo" ascii //weight: 3
        $x_4_6 = "GET /xx/rnde.php?p=%d&f=%d&m=%d HTTP/1.1" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

