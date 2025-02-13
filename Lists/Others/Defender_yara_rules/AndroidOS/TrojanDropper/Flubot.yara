rule TrojanDropper_AndroidOS_Flubot_A_2147811503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Flubot.A"
        threat_id = "2147811503"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Flubot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/demoformalware" ascii //weight: 10
        $x_2_2 = "addFBListener" ascii //weight: 2
        $x_1_3 = "isAppInstalled" ascii //weight: 1
        $x_1_4 = "isPackageInstalled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

