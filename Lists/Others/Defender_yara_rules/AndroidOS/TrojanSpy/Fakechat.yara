rule TrojanSpy_AndroidOS_Fakechat_B_2147833750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakechat.B!MTB"
        threat_id = "2147833750"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakechat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/hulkapp/chatlite" ascii //weight: 1
        $x_1_2 = "newsdata.apk" ascii //weight: 1
        $x_1_3 = "com.system.myapplication.Activities.dcteat" ascii //weight: 1
        $x_1_4 = "newsdata.bundle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

