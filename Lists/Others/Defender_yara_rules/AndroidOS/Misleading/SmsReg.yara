rule Misleading_AndroidOS_SmsReg_A_301471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:AndroidOS/SmsReg.A!xp"
        threat_id = "301471"
        type = "Misleading"
        platform = "AndroidOS: Android operating system"
        family = "SmsReg"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "10.235.148.9/middle/mypageorder.jsp" ascii //weight: 1
        $x_1_2 = "DCAgent_onKillProcessOrExit" ascii //weight: 1
        $x_1_3 = "api.dj111.top:20006/SmsPayServer/getMessage/getSDKMessageJson" ascii //weight: 1
        $x_1_4 = "Android/data/com.door.pay.app/" ascii //weight: 1
        $x_1_5 = "www.zhjnn.com:20002/advert/info/userActions?appId=" ascii //weight: 1
        $x_1_6 = "setOnKeyListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Misleading_AndroidOS_SmsReg_C_301635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:AndroidOS/SmsReg.C!xp"
        threat_id = "301635"
        type = "Misleading"
        platform = "AndroidOS: Android operating system"
        family = "SmsReg"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vr.php?pay_Id=" ascii //weight: 1
        $x_1_2 = ".wxapi.WXPayEntryActivity" ascii //weight: 1
        $x_1_3 = "visitor1.php?pay_Id=" ascii //weight: 1
        $x_1_4 = "unregisterObserver" ascii //weight: 1
        $x_1_5 = "the remote process die" ascii //weight: 1
        $x_1_6 = "php6.qyjuju.com/json2/my.php?pay_Id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Misleading_AndroidOS_SmsReg_B_302525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:AndroidOS/SmsReg.B!xp"
        threat_id = "302525"
        type = "Misleading"
        platform = "AndroidOS: Android operating system"
        family = "SmsReg"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upayapi.piiwan.com" ascii //weight: 1
        $x_1_2 = ".wxapi.WXPayEntryActivity" ascii //weight: 1
        $x_1_3 = "upayapi.upwan.cn" ascii //weight: 1
        $x_1_4 = "unregisterObserver" ascii //weight: 1
        $x_1_5 = "end_Sms_Monitor_Fail" ascii //weight: 1
        $x_1_6 = "www.upay360.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Misleading_AndroidOS_SmsReg_D_302526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:AndroidOS/SmsReg.D!xp"
        threat_id = "302526"
        type = "Misleading"
        platform = "AndroidOS: Android operating system"
        family = "SmsReg"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/umpay/huafubao/download" ascii //weight: 1
        $x_1_2 = "mnsp.juzixiangshui.com/?" ascii //weight: 1
        $x_1_3 = "sms2.upay360.com/getMobile.php" ascii //weight: 1
        $x_1_4 = {78 71 32 2e 31 32 37 37 35 32 37 2e 63 6f 6d 2f 30 39 30 31 3f ?? ?? ?? ?? 3a 2f 2f 31 31 31 2e 31 33 2e 34 37 2e 37 36 3a 38 31 2f 6f 70 65 6e 5f 67 61 74 65 2f 77 65 62 5f 67 61 6d 65 5f 66 65 65 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_5 = "com.upay.pay.upay_sms.service.AlarmService" ascii //weight: 1
        $x_1_6 = "SmsInitObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

