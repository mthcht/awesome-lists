rule TrojanSpy_AndroidOS_Knobot_A_2147756367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Knobot.A!MTB"
        threat_id = "2147756367"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Knobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cealegacy.online" ascii //weight: 1
        $x_1_2 = "botVersion" ascii //weight: 1
        $x_1_3 = "botnetID" ascii //weight: 1
        $x_1_4 = "wppiejpmkijnq = \"eventBot\"" ascii //weight: 1
        $x_1_5 = "Failed to get last known location" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

