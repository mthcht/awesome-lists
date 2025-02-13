rule Backdoor_MacOS_X_CoinThief_A_2147685454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/CoinThief.A"
        threat_id = "2147685454"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "CoinThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72 00 63 68 72 6f 6d 65 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72}  //weight: 2, accuracy: High
        $x_2_2 = {66 73 36 33 34 38 39 32 33 6c 6f 63 6b 00 41 67 65 6e 74}  //weight: 2, accuracy: High
        $x_2_3 = "/tmp/_agn%lu" ascii //weight: 2
        $x_2_4 = "isBitcoinQtInstalled" ascii //weight: 2
        $x_2_5 = {2f 75 73 72 2f 62 69 6e 2f 75 6e 7a 69 70 00 2d 64 00 5f 5f 4d 41 43 4f 53 58 00 69 6e 73 74 61 6c 6c}  //weight: 2, accuracy: High
        $x_2_6 = "POST \\/([^ ]*) HTTP\\/1\\.([01]).*Content-Length: ([0-9]+).*%@%@" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_X_CoinThief_B_2147685638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/CoinThief.B"
        threat_id = "2147685638"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "CoinThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72 00 63 68 72 6f 6d 65 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72}  //weight: 2, accuracy: High
        $x_2_2 = {66 73 36 33 34 38 39 32 33 6c 6f 63 6b 00 41 67 65 6e 74}  //weight: 2, accuracy: High
        $x_2_3 = "/tmp/_agn%lu" ascii //weight: 2
        $x_2_4 = "isBitcoinQtInstalled" ascii //weight: 2
        $x_2_5 = {62 69 74 63 6f 69 6e 51 74 50 61 74 63 68 65 64 00 30 66 30 61 66 63 33 38 30 38 38 61 33 65 30 33 38 64 39 39 35 38 63 65 66 37 37 37 33 63 66 39}  //weight: 2, accuracy: High
        $x_2_6 = "/Xcode/DerivedData/Injector-" ascii //weight: 2
        $x_2_7 = "POST \\/([^ ]*) HTTP\\/1\\.([01]).*Content-Length: ([0-9]+).*%@%@" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

