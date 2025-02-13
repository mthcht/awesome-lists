rule TrojanSpy_AndroidOS_Kamran_A_2147898352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Kamran.A!MTB"
        threat_id = "2147898352"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Kamran"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/kamran/hunzanews" ascii //weight: 1
        $x_1_2 = "uploadCallLogs" ascii //weight: 1
        $x_1_3 = "hunzanews.net" ascii //weight: 1
        $x_1_4 = "callYoutube" ascii //weight: 1
        $x_1_5 = "fetchIsContactsAdded" ascii //weight: 1
        $x_1_6 = "uploadMessages" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

