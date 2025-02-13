rule Trojan_Linux_Xaynnalc_A_2147823667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xaynnalc.A!xp"
        threat_id = "2147823667"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xaynnalc"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/.bash_history" ascii //weight: 1
        $x_1_2 = "/dev/misc/watchdog" ascii //weight: 1
        $x_1_3 = {74 61 72 74 69 6e 67 20 64 64 6f 73 2e 2e 2e 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 10 64 00 00 e8 20 2e 00 10 e4 88 2d 40 ff fc 20 6e 00 0c 1d 50 ff f7 52 ae}  //weight: 1, accuracy: High
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

