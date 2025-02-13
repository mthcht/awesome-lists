rule TrojanSpy_AndroidOS_Smypie_A_2147783791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Smypie.A!MTB"
        threat_id = "2147783791"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Smypie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Try to disable verify apps" ascii //weight: 1
        $x_1_2 = "MSpyIME" ascii //weight: 1
        $x_1_3 = "FORCE_GPS" ascii //weight: 1
        $x_1_4 = "Monitor started" ascii //weight: 1
        $x_1_5 = "Remove helper app" ascii //weight: 1
        $x_1_6 = "location_providers_allowed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

