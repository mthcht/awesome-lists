rule Backdoor_MacOS_Longage_C_2147935081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Longage.C!MTB"
        threat_id = "2147935081"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Longage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 21 ff fc 54 21 00 34 38 00 00 00 90 01 00 00 94 21 ff c0 80 7a 00 00 38 9a 00 04 3b 63 00 01 57 7b 10 3a 7c a4 da 14 7c a6 2b 78 80 06 00 00 38 c6 00 04 2c 00 00 00 40 82 ff f4 48 00 30 ad 48 00 3f b4 7c 08 02 a6 42 9f 00 05 7d 88 02 a6}  //weight: 1, accuracy: High
        $x_1_2 = {81 09 00 0c 7c 43 e9 2e 7f a3 eb 78 90 0b 00 04 91 4b 00 08 91 0b 00 0c 88 09 00 18 80 49 00 10 81 49 00 14 98 0b 00 18 90 4b 00 10 91 4b 00 14 48 00 40 61 3c 40 00 00 7d 63 ea 14 39 22 5e 64 80 42 5e 64 80 09 00 04 81 49 00 08 81 09 00 0c 7c 43 e9 2e 7f a3 eb 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

