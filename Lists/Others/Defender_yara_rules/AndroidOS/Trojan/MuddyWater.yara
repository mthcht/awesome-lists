rule Trojan_AndroidOS_MuddyWater_A_2147783489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MuddyWater.A"
        threat_id = "2147783489"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MuddyWater"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "classHelper/Field/SystemInfoField;" ascii //weight: 2
        $x_1_2 = "DO_PORT_SCAN" ascii //weight: 1
        $x_1_3 = "IS_CLIETNT_CONNECTED" ascii //weight: 1
        $x_1_4 = "runSpyService" ascii //weight: 1
        $x_1_5 = "INSTALLED_APP_HEADER" ascii //weight: 1
        $x_1_6 = "getSmartCallLog" ascii //weight: 1
        $x_1_7 = "run_spy_service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

