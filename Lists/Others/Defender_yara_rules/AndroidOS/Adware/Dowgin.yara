rule Adware_AndroidOS_Dowgin_A_361110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Dowgin.A!MTB"
        threat_id = "361110"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Dowgin"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 31 00 62 00 ?? ?? 13 01 0d 00 71 10 ?? ?? 01 00 0c 01 6e 20 ?? ?? 10 00 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = "onStartCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

