rule Trojan_MacOS_ApFellDownload_A_2147890290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ApFellDownload.A"
        threat_id = "2147890290"
        type = "Trojan"
        platform = "MacOS: "
        family = "ApFellDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f [0-32] 3a 38 30 [0-37] 2e 6a 73 [0-16] 66 61 69 6c 65 64 20 74 6f 20 66 65 74 63 68 20 64 61 74 61 20 66 72 6f 6d 20 74 68 65 20 75 72 6c}  //weight: 2, accuracy: Low
        $x_3_2 = {48 bf 4a 61 76 61 53 63 72 69 48 be 70 74 00 00 00 00 00 ea e8 60 2b 00 00}  //weight: 3, accuracy: High
        $x_3_3 = {40 29 8c d2 c0 2e ac f2 60 6a cc f2 40 2e ed f2 01 8e 8e d2 01 40 fd f2 70 06 00 94}  //weight: 3, accuracy: High
        $x_2_4 = "_OBJC_CLASS_$_OSAScript" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

