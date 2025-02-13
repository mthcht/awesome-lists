rule MonitoringTool_AndroidOS_TeleBot_A_405909_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TeleBot.A!MTB"
        threat_id = "405909"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TeleBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BotUtilsKt" ascii //weight: 1
        $x_1_2 = "requestAccessToScreenshots" ascii //weight: 1
        $x_10_3 = "com.remotebot.android.presentation" ascii //weight: 10
        $x_1_4 = "ttps://remote-bot.com/" ascii //weight: 1
        $x_1_5 = "sendPhoto" ascii //weight: 1
        $x_1_6 = "sendText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

