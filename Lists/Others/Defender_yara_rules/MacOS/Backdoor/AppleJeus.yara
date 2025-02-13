rule Backdoor_MacOS_AppleJeus_A_2147734485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/AppleJeus.A"
        threat_id = "2147734485"
        type = "Backdoor"
        platform = "MacOS: "
        family = "AppleJeus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Moz&Wie;#t/6T!2y" ascii //weight: 1
        $x_1_2 = {2d 2d 6a 65 75 73 0d 0a 43 6f 6e 74 65 6e 74 2d}  //weight: 1, accuracy: High
        $x_1_3 = {2f 76 61 72 2f 7a 64 69 66 66 73 65 63 00 46 69 6c 65 20 6f 70 65 6e 20 66 61 69 6c 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

