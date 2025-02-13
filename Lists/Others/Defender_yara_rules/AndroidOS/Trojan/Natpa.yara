rule Trojan_AndroidOS_Natpa_A_2147837177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Natpa.A!MTB"
        threat_id = "2147837177"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Natpa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.iapp.mmapp" ascii //weight: 1
        $x_1_2 = "ZYF_ChannelID.txt" ascii //weight: 1
        $x_1_3 = "/down_dialog_install.png" ascii //weight: 1
        $x_1_4 = "apk.boya1993.com" ascii //weight: 1
        $x_1_5 = "getSmsCenter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

