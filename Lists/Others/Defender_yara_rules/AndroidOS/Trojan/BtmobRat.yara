rule Trojan_AndroidOS_BtmobRat_A_2147950257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BtmobRat.A!MTB"
        threat_id = "2147950257"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BtmobRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 10 15 00 03 00 0c 00 6e 10 23 1a 00 00 0c 00 62 01 8f 07 12 12 33 10 04 00 01 20 28 02 12 00 6e 30 1c 00 13 00 6e 10 17 00 03 00 6e 10 95 19 03 00 0c 00 39 00 03 00 0e 00 54 00 ad 07}  //weight: 1, accuracy: High
        $x_1_2 = {6e 10 15 00 02 00 0c 00 55 00 35 08 38 00 18 00 6e 10 15 00 02 00 0c 00 12 01 5c 01 35 08 6e 10 15 00 02 00 0c 00 6e 10 15 00 02 00 0c 01 6e 10 22 1a 01 00 0c 01 71 20 1c 1a 10 00 0e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

