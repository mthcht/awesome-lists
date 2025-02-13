rule TrojanSpy_AndroidOS_Gepew_A_2147786559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gepew.A.MTB"
        threat_id = "2147786559"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gepew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KR_NHBank.apk" ascii //weight: 1
        $x_1_2 = "app.dwonload.complate" ascii //weight: 1
        $x_1_3 = "autoChangeApk" ascii //weight: 1
        $x_1_4 = "SMS_SEND_ACTIOIN" ascii //weight: 1
        $x_1_5 = "korea.kr_nhbank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Gepew_B_2147823812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gepew.B!MTB"
        threat_id = "2147823812"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gepew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gook.jkub.com" ascii //weight: 1
        $x_1_2 = "SMSAllCompate" ascii //weight: 1
        $x_1_3 = "getPhoneContacts" ascii //weight: 1
        $x_1_4 = "DeleteCall" ascii //weight: 1
        $x_1_5 = "autoChangeApps" ascii //weight: 1
        $x_1_6 = "KR_NHBank.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

