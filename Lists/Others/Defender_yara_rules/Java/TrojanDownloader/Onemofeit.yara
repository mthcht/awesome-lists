rule TrojanDownloader_Java_Onemofeit_A_2147711446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Onemofeit.A"
        threat_id = "2147711446"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Onemofeit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_12_1 = "://23.88.113.18/Monday" ascii //weight: 12
        $x_2_2 = "chama32.jpeg" ascii //weight: 2
        $x_2_3 = "principal32.jpeg" ascii //weight: 2
        $x_2_4 = "pg.jpeg" ascii //weight: 2
        $x_2_5 = "chama64.jpeg" ascii //weight: 2
        $x_2_6 = "principal64.jpeg" ascii //weight: 2
        $x_1_7 = "32.jpeg" ascii //weight: 1
        $x_1_8 = "64.jpeg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_12_*) and 2 of ($x_1_*))) or
            ((1 of ($x_12_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

