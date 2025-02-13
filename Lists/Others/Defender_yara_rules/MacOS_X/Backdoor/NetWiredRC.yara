rule Backdoor_MacOS_X_NetWiredRC_A_2147661504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/NetWiredRC.A"
        threat_id = "2147661504"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "NetWiredRC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2f 74 6d 70 2f 25 73 00 43 4f 4e 4e 45 43 54 ?? 25 73 3a 25 64 ?? 48 54 54 50}  //weight: 5, accuracy: Low
        $x_5_2 = {2f 74 6d 70 2f 2e 25 73 00 25 73 2f 25 73 2e 61 70 70 00 25 73 2f 43 6f 6e 74 65 6e 74 73}  //weight: 5, accuracy: High
        $x_1_3 = "select *  from moz_logins" ascii //weight: 1
        $x_1_4 = "%s/Library/SeaMonkey" ascii //weight: 1
        $x_1_5 = "%s/.Library/Thunderbird" ascii //weight: 1
        $x_1_6 = "%s/.Library/Opera/wand.dat" ascii //weight: 1
        $x_1_7 = "%s/.Library/Mozilla/Firefox" ascii //weight: 1
        $x_1_8 = "%s/Library/Application Support/Firefox" ascii //weight: 1
        $x_10_9 = "RGI28DQ30QB8Q1F7" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

