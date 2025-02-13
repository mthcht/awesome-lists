rule Trojan_AndroidOS_Defensorid_C_2147783285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Defensorid.C"
        threat_id = "2147783285"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Defensorid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/brazil/android/free/CommandService" ascii //weight: 1
        $x_1_2 = "Check_over_permission" ascii //weight: 1
        $x_1_3 = "new_screen_ask" ascii //weight: 1
        $x_1_4 = "Export_Info_Dev" ascii //weight: 1
        $x_1_5 = "AccessEnable_Check" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

