rule TrojanClicker_AndroidOS_Ubsod_A_2147829551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:AndroidOS/Ubsod.A!MTB"
        threat_id = "2147829551"
        type = "TrojanClicker"
        platform = "AndroidOS: Android operating system"
        family = "Ubsod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoopMeAdHolder" ascii //weight: 1
        $x_1_2 = "getCellLocation" ascii //weight: 1
        $x_1_3 = "dialog_download_activity_title" ascii //weight: 1
        $x_1_4 = "AdActivity" ascii //weight: 1
        $x_1_5 = "lockNow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

