rule Trojan_MacOS_KCSteal_D_2147934759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/KCSteal.D!MTB"
        threat_id = "2147934759"
        type = "Trojan"
        platform = "MacOS: "
        family = "KCSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 89 fb 48 8b 35 05 2f 00 00 48 8d 15 0e 1a 00 00 ff 15 58 19 00 00 48 89 d8 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb 48 83 c7 28 31 f6 e8 65 00 00 00 48 8d 7b 20 31 f6 e8 5a 00 00 00 48 8d 7b 18 31 f6 e8 4f 00 00 00 48 8d 7b 10 31 f6 e8 44 00 00 00 48 83 c3 08 48 89 df 31 f6 48 83 c4 08 5b 5d e9 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_KCSteal_C_2147935665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/KCSteal.C!MTB"
        threat_id = "2147935665"
        type = "Trojan"
        platform = "MacOS: "
        family = "KCSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 89 fb 48 8b 35 58 3b 00 00 48 8d 15 f1 23 00 00 ff 15 e3 22 00 00 48 89 d8 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb 48 83 c7 28 31 f6 e8 71 00 00 00 48 8d 7b 20 31 f6 e8 66 00 00 00 48 8d 7b 18 31 f6 e8 5b 00 00 00 48 8d 7b 10 31 f6 e8 50 00 00 00 48 83 c3 08 48 89 df 31 f6 48 83 c4 08 5b 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

