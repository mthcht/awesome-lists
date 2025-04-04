rule Trojan_AndroidOS_LockScreen_D_2147937879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockScreen.D!MTB"
        threat_id = "2147937879"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 06 07 17 15 08 03 7f 12 09 6e 30 15 00 87 09 0c 07 1f 07 14 00 5b 67 10 00 07 06 22 07 1a 00 07 7d 07 d7 07 d8 07 09 70 20 21 00 98 00 5b 67 0c 00 07 06 07 07 54 77 10 00 15 08 05 7f 6e 20 18 00 87 00 0c 07 1f 07 19 00 5b 67 0e 00 07 06 07 07 54 77 10 00 14 08 02 00 05 7f}  //weight: 1, accuracy: High
        $x_1_2 = {0c 04 07 42 07 24 1a 05 6a 00 13 06 80 00 6e 30 13 00 54 06 0c 04 07 43 22 04 3b 00 07 4a 07 a4 07 a5 22 06 01 00 07 6a 07 a6 07 a7 07 08 70 20 01 00 87 00 70 20 48 00 65 00 07 42 07 24 6e 10 49 00 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

