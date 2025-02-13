rule TrojanDropper_AndroidOS_BankrAgt_A_2147782633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/BankrAgt.A!MTB"
        threat_id = "2147782633"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "BankrAgt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 1a 05 01 00 6e 20 ?? ?? 53 00 6e 10 ?? ?? 03 00 0c 03 6e 10 ?? ?? 03 00 0c 03 6e 20 ?? ?? 32 00 6e 10 07 00 08 00 0c 03 6e 20 ?? ?? ?? 00 0c 03 12 06 46 03 03 06 6e 20 ?? ?? 32 00 6e 10 ?? ?? 02 00 0c 02 6e 20 14 00 21 00 0c 01 13 02 0b 00 23 22 ?? ?? 6e 20 ?? ?? 21 00 13 03 08 00 48 06 02 03 d5 66 ff 00 e0 06 06 10 13 07 09 00 48 07 02 07 d5 77 ff 00 e0 03 07 08 b6 63 13 06 0a 00 48 02 02 06 d5 22 ff 00 b6 32 6e 10 ?? ?? ?? 00 0a 03 70 53 ?? ?? ?? ?? 6e 10 ?? ?? 00 00 0c 00 70 10 ?? ?? ?? 00 0c 01 22 02 ?? ?? 70 20 ?? ?? ?? 00 6e 20 ?? ?? ?? 00 6e 10 ?? ?? ?? 00 22 00 ?? ?? 22 02 ?? ?? 70 10 ?? ?? ?? 00 6e 10 08 00 08 00}  //weight: 2, accuracy: Low
        $x_1_2 = "loadLibrary" ascii //weight: 1
        $x_1_3 = "getAssets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

