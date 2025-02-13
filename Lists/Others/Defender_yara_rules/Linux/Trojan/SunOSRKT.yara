rule Trojan_Linux_SunOSRKT_A_2147795485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SunOSRKT.A!xp"
        threat_id = "2147795485"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SunOSRKT"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsof_filters" ascii //weight: 1
        $x_1_2 = "/usr/lib/libX.a/uconf.inv" ascii //weight: 1
        $x_1_3 = "/usr/lib/libX.a/bin/" ascii //weight: 1
        $x_1_4 = {9d e3 bc 90 11 00 00 86 13 00 00 86 15 00 00 86 d0 02 23 28 d2 02 63 60 40 00 00 73 d4 02 a3 6c b0 92 20 00 22 80 00 08 11 00 00 46}  //weight: 1, accuracy: High
        $x_1_5 = {40 00 41 98 90 07 bd f0 11 00 00 86 13 00 00 86 15 00 00 86 d0 02 23 28 d2 02 63 60 40 00 00 52 d4 02 a3 74 92 92 20 00 12 80 00 04 b0 07 bc f0 11 00 00 46 92 12 20 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

