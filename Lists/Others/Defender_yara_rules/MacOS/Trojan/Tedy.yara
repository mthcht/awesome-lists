rule Trojan_MacOS_Tedy_LR_2147981842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Tedy.LR!MTB"
        threat_id = "2147981842"
        type = "Trojan"
        platform = "MacOS: "
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {08 0d 09 8b e8 17 00 f9 08 10 80 52 e8 1b 00 39 e8 1b 40 39 2a 05 00 91 ea 3b 00 f9 c8 6a 29 38 e8 3b 40 f9 1f e5 00 f1}  //weight: 20, accuracy: High
        $x_10_2 = {4b 25 c9 9a ec 3b 40 f9 8d 05 00 91 ed 3b 00 f9 cb 6a 2c 38 08 05 00 51 29 21 00 51 28 ff ff 36}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Tedy_LR_2147981842_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Tedy.LR!MTB"
        threat_id = "2147981842"
        type = "Trojan"
        platform = "MacOS: "
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {28 00 00 4a 29 0e 81 52 89 4a a9 72 09 01 09 4a 2a 00 00 0b 49 01 09 0b 8a 30 97 52 ca 55 b2 72 2a 01 0a 4a 2b 92 99 52 2b 17 ae 72 08 01 0b 4a 48 01 08 4b 08 01 0a 0a eb 64 81 52 4b 30 b1 72 29 01 0b 0a}  //weight: 20, accuracy: High
        $x_10_2 = {29 01 0a 0a 28 01 08 4a e8 27 00 b9 e8 2f 40 b9 a9 02 91 52 08 7d 09 1b e9 27 40 b9 08 2d 89 0b e8 2f 00 b9 e8 2f 40 b9 29 01 85 52 08 01 09 0a e9 27 40 b9 6a e0 82 12 28 01 08 4b 08 01 0a 0b e8 27 00 b9 e8 27 40 b9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Tedy_LR_2147981842_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Tedy.LR!MTB"
        threat_id = "2147981842"
        type = "Trojan"
        platform = "MacOS: "
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {ea 03 40 b9 29 21 8a 0b e9 07 00 b9 e9 07 40 b9 aa 40 8c 52 29 01 0a 2a ea 07 40 b9 4b 20 86 52 4a 01 0b 0a 49 01 09 4a e9 03 00 b9 e9 03 40 b9 aa 4b 84 52 49 21 09 4a ea 07 40 b9 29 01 0a 0b e9 07 00 b9}  //weight: 20, accuracy: High
        $x_10_2 = {ea 7d 80 52 ca 8d ad 72 0a 01 0a 4a cb d2 86 52 ab 71 bd 72 2a 01 0a 4b 4b 01 0b 0b 69 01 09 4a 48 01 08 0b 28 01 08 4b e9 11 91 52 e9 ae a3 72 49 01 09 0b 08 01 09 4a c9 b7 9a 52 c9 ba a4 72 09 01 09 4a 2b 01 0a 0a 2c 48 85 52 2c 45 bb 72 08 01 0c 4a ec e4 9a 52}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

