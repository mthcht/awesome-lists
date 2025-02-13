rule Trojan_Win32_Miemoes_A_2147622869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miemoes.A"
        threat_id = "2147622869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miemoes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff ff 8b f0 bb 84 ff ff ff 81 36 66 d6 ba 13 83 c6 04 43 75 f4 68 ff 00 00 00 8d 84 24 43 05 00 00 50 6a 00}  //weight: 10, accuracy: High
        $x_1_2 = "miekiemoes" ascii //weight: 1
        $x_1_3 = "rds.yahoo" ascii //weight: 1
        $x_1_4 = "format=rss" ascii //weight: 1
        $x_1_5 = {69 63 71 00 79 69 6d 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

