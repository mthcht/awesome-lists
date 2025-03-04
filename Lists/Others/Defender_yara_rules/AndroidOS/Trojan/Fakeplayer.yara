rule Trojan_AndroidOS_Fakeplayer_2147650213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeplayer"
        threat_id = "2147650213"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeplayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c d0 9f d0 be d0 b4 d0 be d0 b6 d0 b4 d0 b8 d1 82 d0 b5 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {d1 80 d1 81 d0 be d0 bd d0 b0 d0 bb d1 8c d0 bd d0 be d0 b3 d0 be 20 d0 ba d0 bb d1 8e d1 87 d0 b0 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_2_3 = "canwe" ascii //weight: 2
        $x_5_4 = {28 4c 6f 72 67 2f 6d 65 2f 61 6e 64 72 6f 69 64 61 70 70 6c 69 63 61 74 69 6f 6e 31 2f 4d 6f 76 69 65 50 6c 61 79 65 72 3b 00}  //weight: 5, accuracy: High
        $x_5_5 = "/telephony/SmsManager;" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

