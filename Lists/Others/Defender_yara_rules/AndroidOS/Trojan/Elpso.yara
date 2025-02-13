rule Trojan_AndroidOS_Elpso_A_2147784812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Elpso.A!MTB"
        threat_id = "2147784812"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Elpso"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eclipsplayer.com" ascii //weight: 1
        $x_1_2 = "vod.vod4.mobi" ascii //weight: 1
        $x_1_3 = "sendMultipartTextMessage" ascii //weight: 1
        $x_1_4 = "Pay-Per-Click modus" ascii //weight: 1
        $x_1_5 = "usePrivateMailbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

