rule TrojanSpy_AndroidOS_GlodEagl_A_2147759741_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GlodEagl.A!MTB"
        threat_id = "2147759741"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GlodEagl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/golden/eagle/" ascii //weight: 1
        $x_1_2 = "/data/data/com.golden.eagle/" ascii //weight: 1
        $x_1_3 = "content://sms/inbox" ascii //weight: 1
        $x_1_4 = "StartRecord" ascii //weight: 1
        $x_1_5 = "callRecoder.amr" ascii //weight: 1
        $x_1_6 = "getCallHistory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_GlodEagl_B_2147890544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GlodEagl.B!MTB"
        threat_id = "2147890544"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GlodEagl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ht.52vpen.net" ascii //weight: 1
        $x_1_2 = "api.hawar.cn" ascii //weight: 1
        $x_1_3 = "api.xoh.cn" ascii //weight: 1
        $x_1_4 = "/system/app/plugin.apk" ascii //weight: 1
        $x_1_5 = "com/callrecorder/service" ascii //weight: 1
        $x_1_6 = "defaultTrojan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

