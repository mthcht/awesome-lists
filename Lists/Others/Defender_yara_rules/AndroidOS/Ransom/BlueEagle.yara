rule Ransom_AndroidOS_BlueEagle_A_2147808761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/BlueEagle.A!MTB"
        threat_id = "2147808761"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "BlueEagle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Landroid/provider/CallLog$Calls" ascii //weight: 1
        $x_10_2 = {0a 05 2b 05 ?? ?? 00 00 d8 05 06 0a 01 46 01 5a 07 05 01 a0 2b 00 ?? ?? 00 00 98 00 07 08 1a 01 7b 00 07 51 d8 00 00 ff df 04 00 20 32 62 ?? ?? 49 00 01 02 95 05 0b 04 b7 05 d8 0b 0b 01 d8 00 02 01 8e 55 50 05 01 02 01 02 28 f1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

