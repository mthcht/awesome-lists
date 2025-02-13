rule Adware_AndroidOS_Ashas_A_299156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Ashas.A"
        threat_id = "299156"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Ashas"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ASHAS" ascii //weight: 2
        $x_2_2 = "CODE_CLIENT_CONFIG" ascii //weight: 2
        $x_2_3 = "ALARM_SCHEDULE_MINUTES" ascii //weight: 2
        $x_1_4 = "ASadsdk" ascii //weight: 1
        $x_1_5 = "FirstRunService onCreate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

