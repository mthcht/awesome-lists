rule Trojan_AndroidOS_Fakechatgpt_A_2147841681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakechatgpt.A"
        threat_id = "2147841681"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakechatgpt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "android.app.action.ADD_DEVICE_ADMIN" ascii //weight: 1
        $x_1_2 = "/system/bin/screencap -p /sdcard/rootSU.png" ascii //weight: 1
        $x_1_3 = "SMS[" ascii //weight: 1
        $x_1_4 = "onDisableRequested" ascii //weight: 1
        $x_1_5 = "/exit/chat" ascii //weight: 1
        $x_1_6 = "Write a message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakechatgpt_B_2147841682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakechatgpt.B"
        threat_id = "2147841682"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakechatgpt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://onesignal.modobomco.com/" ascii //weight: 1
        $x_1_2 = "+4761597" ascii //weight: 1
        $x_1_3 = "huycoi" ascii //weight: 1
        $x_1_4 = "SEND_AIS" ascii //weight: 1
        $x_1_5 = "ChatGPT" ascii //weight: 1
        $x_1_6 = "mcc_mnc" ascii //weight: 1
        $x_1_7 = "sensms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

