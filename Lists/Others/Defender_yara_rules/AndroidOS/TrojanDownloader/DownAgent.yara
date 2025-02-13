rule TrojanDownloader_AndroidOS_DownAgent_A_2147774150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/DownAgent.A!MTB"
        threat_id = "2147774150"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "DownAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/haleycommet/darkweb/playstore/" ascii //weight: 2
        $x_2_2 = "cdn.discordapp.com/attachments/" ascii //weight: 2
        $x_1_3 = "/Update.apk" ascii //weight: 1
        $x_1_4 = "com.android.packageinstaller:id/permission_allow_button" ascii //weight: 1
        $x_1_5 = "/PermAct;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

