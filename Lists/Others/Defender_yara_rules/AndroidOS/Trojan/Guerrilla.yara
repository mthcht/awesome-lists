rule Trojan_AndroidOS_Guerrilla_A_2147759372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Guerrilla.A!MTB"
        threat_id = "2147759372"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Guerrilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "numberInContract" ascii //weight: 1
        $x_1_2 = "getSmsCount" ascii //weight: 1
        $x_1_3 = "canKillPhoneProcess" ascii //weight: 1
        $x_1_4 = "SmsHook" ascii //weight: 1
        $x_1_5 = "delSendMsg" ascii //weight: 1
        $x_1_6 = "sm_sp_ws_url" ascii //weight: 1
        $x_1_7 = "hookPhone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Guerrilla_A_2147759372_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Guerrilla.A!MTB"
        threat_id = "2147759372"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Guerrilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setPremiumSmsPermission" ascii //weight: 1
        $x_1_2 = "zh.yomobi.net:8080" ascii //weight: 1
        $x_1_3 = "pauseDownloadAds" ascii //weight: 1
        $x_1_4 = "sendMessage" ascii //weight: 1
        $x_1_5 = "zh_ota.log" ascii //weight: 1
        $x_2_6 = "com.android.goobrw.sdk.compress.helpreceiver.HelpXReceiver" ascii //weight: 2
        $x_1_7 = "AdManager.java" ascii //weight: 1
        $x_1_8 = "android.intent.action.BOOT_COMPLETED" ascii //weight: 1
        $x_1_9 = "games.androidad.net:9080/upload/jar/f6.jar " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

