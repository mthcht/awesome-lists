rule Trojan_AndroidOS_Mobtez_A_2147784811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobtez.A!MTB"
        threat_id = "2147784811"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobtez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startSmsFilters" ascii //weight: 1
        $x_1_2 = "maxSendCount" ascii //weight: 1
        $x_1_3 = "sendSmsPeriod" ascii //weight: 1
        $x_1_4 = "OperaUpdaterActivity" ascii //weight: 1
        $x_1_5 = "Lorg/MobileDb/MobileDatabase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

