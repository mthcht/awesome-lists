rule Backdoor_MacOS_Getshell_2147742992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Getshell"
        threat_id = "2147742992"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Getshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 89 e5 83 e4 f0 83 ec 10 8b 5d 04 89 5c 24 00 8d 4d 08 89 4c 24 04 83 c3 01 c1 e3 02 01 cb 89 5c 24 08 8b 03 83 c3 04 85 c0 75 f7 89 5c 24 0c e8 2c 00 00 00 89 44 24 00 e8 45 30 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 53 83 ec 04 e8 00 00 00 00 5b 8d 83 2a 00 00 00 ff d0 b8 00 00 00 00 83 c4 04 5b c9 c3}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 6d 61 69 6e 00 5f 70 61 79 6c 6f 61 64 00 73 74 61 72 74 00 5f 65 78 69 74}  //weight: 1, accuracy: High
        $x_1_4 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

