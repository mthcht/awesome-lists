rule Backdoor_MacOS_WindTail_A_2147734482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/WindTail.A"
        threat_id = "2147734482"
        type = "Backdoor"
        platform = "MacOS: "
        family = "WindTail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 35 4f 69 44 39 4b 49 53 77 3d 3d 00 44 6f 70 2e 64 61 74 00 46 75 6e 67 2e 64 61 74 00 61 61 67 48 64 44 47 2b 59 50 39 42 45 6d 48 4c 43 67}  //weight: 1, accuracy: High
        $x_1_2 = {2e 61 70 70 00 2f 62 69 6e 2f 73 68 00 2d 63 00 73 6f 6e 67 2e 64 61 74 00 23 23 23 23 23 00 4b 45 59 5f 50 41 54 48 00 4b 45 59 5f 41 54 54 52 00 4f 61 49 63 78 58 44 70 2f 59 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

