rule MonitoringTool_AndroidOS_Lypro_A_299474_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Lypro.A!MTB"
        threat_id = "299474"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Lypro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "locateme_pro2.IGNORE_ME" ascii //weight: 1
        $x_1_2 = "FindMe" ascii //weight: 1
        $x_1_3 = "locate_key_pro" ascii //weight: 1
        $x_1_4 = "LocateYourPhonePRO" ascii //weight: 1
        $x_1_5 = "getLastKnownLocation" ascii //weight: 1
        $x_1_6 = "Les/themove/locateme_pro2/LocationService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

