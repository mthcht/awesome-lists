rule TrojanDownloader_AndroidOS_SMSAgent_A_2147788200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/SMSAgent.A!xp"
        threat_id = "2147788200"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "SMSAgent"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deleteSendSms thread start" ascii //weight: 1
        $x_1_2 = "115.28.52.43:9000.123/tabscr/sybb/appclient//download.service?" ascii //weight: 1
        $x_1_3 = "mmpm/getWimiPayMore?channel=0001&imsi=" ascii //weight: 1
        $x_2_4 = "com/chinaMobile/MobileAgent" ascii //weight: 2
        $x_1_5 = "MSG_DWONLOAD_APPDOWNLOAD_SERVICE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_AndroidOS_SMSAgent_B_2147788999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/SMSAgent.B!xp"
        threat_id = "2147788999"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "SMSAgent"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.GAOANDROID.COM/zj/20151106.apk" ascii //weight: 1
        $x_1_2 = "91.xuanguawl.cn:8091/bmbmbm/info/getcpinfo" ascii //weight: 1
        $x_1_3 = "KILL---appDownload" ascii //weight: 1
        $x_2_4 = "www.zhjnn.com:20002/advert/app/list" ascii //weight: 2
        $x_2_5 = "xixi.dj111.top:20006/SmsPayServer/sms/sdkUpdate/index?" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

