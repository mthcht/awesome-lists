rule TrojanSpy_AndroidOS_Capchator_A_2147810029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Capchator.A!MTB"
        threat_id = "2147810029"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Capchator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".ru/Captchator.apk" ascii //weight: 2
        $x_1_2 = "LoadBanker" ascii //weight: 1
        $x_1_3 = "InstalledBanks" ascii //weight: 1
        $x_1_4 = "pm install" ascii //weight: 1
        $x_1_5 = "UploadFileToUrlAndDel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

