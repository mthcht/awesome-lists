rule Adware_AndroidOS_Mobby_A_364287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobby.A!MTB"
        threat_id = "364287"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobby"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "io/mobby/loader/ap" ascii //weight: 1
        $x_2_2 = "Cryoloader" ascii //weight: 2
        $x_1_3 = "getServer" ascii //weight: 1
        $x_2_4 = "revolumbus.space" ascii //weight: 2
        $x_1_5 = "startService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

