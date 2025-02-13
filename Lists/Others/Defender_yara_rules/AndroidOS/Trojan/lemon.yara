rule Trojan_AndroidOS_lemon_A_2147834892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/lemon.A!MTB"
        threat_id = "2147834892"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "lemon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setIMEIAndVersion" ascii //weight: 1
        $x_1_2 = "md5_network" ascii //weight: 1
        $x_1_3 = "MESSAGE_INTO_ONLINE_BOOKS" ascii //weight: 1
        $x_1_4 = "autoUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

