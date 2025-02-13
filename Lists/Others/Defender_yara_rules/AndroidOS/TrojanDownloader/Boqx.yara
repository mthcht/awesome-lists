rule TrojanDownloader_AndroidOS_Boqx_A_2147813257_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Boqx.A!MTB"
        threat_id = "2147813257"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Boqx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lqs/jianjian/wallpaper/qcnh" ascii //weight: 2
        $x_1_2 = "/download/.um/apk" ascii //weight: 1
        $x_1_3 = "talkphone.cn/Down/softdownload.aspx" ascii //weight: 1
        $x_1_4 = "com/ap/Utils" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

