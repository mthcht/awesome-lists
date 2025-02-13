rule Backdoor_Linux_Xbash_A_2147776297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Xbash.gen!A!!Xbash.gen!A"
        threat_id = "2147776297"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Xbash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Xbash: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DROP DATABASE" ascii //weight: 10
        $x_5_2 = "Bitcoin" ascii //weight: 5
        $x_5_3 = "BTC " ascii //weight: 5
        $x_1_4 = "PLEASE_READ_ME_XYZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

