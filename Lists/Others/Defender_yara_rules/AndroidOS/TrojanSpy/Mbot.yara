rule TrojanSpy_AndroidOS_Mbot_A_2147827432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mbot.A!MTB"
        threat_id = "2147827432"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Linstall/apps/" ascii //weight: 2
        $x_1_2 = "/inj.zip" ascii //weight: 1
        $x_1_3 = "/InjectProc;" ascii //weight: 1
        $x_1_4 = "/CommandService;" ascii //weight: 1
        $x_1_5 = "/Cripts;" ascii //weight: 1
        $x_1_6 = "/Scrynlock;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

