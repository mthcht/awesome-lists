rule Ransom_AndroidOS_covidransom_A_2147783592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/covidransom.A"
        threat_id = "2147783592"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "covidransom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "setAppAsHidden" ascii //weight: 2
        $x_2_2 = "shouldRestrictDeviceUsage" ascii //weight: 2
        $x_2_3 = "startBlockedActivity" ascii //weight: 2
        $x_1_4 = "requestBatteryOptimization" ascii //weight: 1
        $x_1_5 = "queryInstalledApps" ascii //weight: 1
        $x_1_6 = "secretPin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

