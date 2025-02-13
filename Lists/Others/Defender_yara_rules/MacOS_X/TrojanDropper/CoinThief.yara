rule TrojanDropper_MacOS_X_CoinThief_A_2147685453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MacOS_X/CoinThief.A"
        threat_id = "2147685453"
        type = "TrojanDropper"
        platform = "MacOS_X: "
        family = "CoinThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 6f 6e 74 65 6e 74 73 2f 5f 43 6f 64 65 53 69 67 6e 61 74 75 72 65 00 2e 64 53 59 4d 00 2e 73 69 67}  //weight: 2, accuracy: High
        $x_2_2 = {2f 75 73 72 2f 62 69 6e 2f 74 61 72 00 2d 78 43 00 2d 66}  //weight: 2, accuracy: High
        $x_2_3 = {66 73 36 33 34 38 39 32 33 6c 6f 63 6b 00 41 67 65 6e 74}  //weight: 2, accuracy: High
        $x_2_4 = "L2Jpbi9sYXVuY2hjdGw=" ascii //weight: 2
        $x_2_5 = "RXh0ZW5zaW9uLmNocm9tZQ==" ascii //weight: 2
        $x_2_6 = "U2FmYXJpL0V4dGVuc2lvbnM=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

