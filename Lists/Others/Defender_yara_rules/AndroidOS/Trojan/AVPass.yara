rule Trojan_AndroidOS_AVPass_A_2147829883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AVPass.A!MTB"
        threat_id = "2147829883"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AVPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ttp://interface.57.net" ascii //weight: 2
        $x_2_2 = "zxly_ignore_appgrade_list" ascii //weight: 2
        $x_1_3 = "cmd=get_info_" ascii //weight: 1
        $x_1_4 = "FirstTimeOpenAppText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

