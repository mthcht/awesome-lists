rule Trojan_AndroidOS_Tangbot_A_2147827166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Tangbot.A"
        threat_id = "2147827166"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Tangbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "send_log_injects" ascii //weight: 2
        $x_2_2 = "Lstation/fairly/because" ascii //weight: 2
        $x_2_3 = "resetLoadApp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

