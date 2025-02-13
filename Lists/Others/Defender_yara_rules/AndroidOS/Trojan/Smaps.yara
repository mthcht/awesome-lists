rule Trojan_AndroidOS_Smaps_A_2147906020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smaps.A!MTB"
        threat_id = "2147906020"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smaps"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/system/update_setting" ascii //weight: 1
        $x_1_2 = "Oasetting" ascii //weight: 1
        $x_1_3 = "com/launcher/setting" ascii //weight: 1
        $x_1_4 = "vk.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

