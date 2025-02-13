rule Adware_AndroidOS_Mobhey_A_355414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobhey.A!MTB"
        threat_id = "355414"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobhey"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ad.mail.ru/mobile/" ascii //weight: 1
        $x_1_2 = "com/cootek/iconface" ascii //weight: 1
        $x_1_3 = "com/my/target/ads/MyTargetActivity" ascii //weight: 1
        $x_1_4 = "TracerActivityLifecycleCallback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

