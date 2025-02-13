rule Trojan_AndroidOS_Ginp_A_2147782861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ginp.A"
        threat_id = "2147782861"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ginp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXTENDED_INJECTION" ascii //weight: 1
        $x_1_2 = "startHiddenSMSActivity" ascii //weight: 1
        $x_1_3 = "sendInboxMessagesToServer" ascii //weight: 1
        $x_1_4 = "startAccessibilityWatcher" ascii //weight: 1
        $x_1_5 = "HIDE_DELAY_START_WINDOW" ascii //weight: 1
        $x_1_6 = "DEBUG_TO_API" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

