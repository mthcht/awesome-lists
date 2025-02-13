rule TrojanSpy_AndroidOS_Teardroid_A_2147813764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Teardroid.A!MTB"
        threat_id = "2147813764"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Teardroid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.example.teardroidv2" ascii //weight: 1
        $x_1_2 = "getVictimID" ascii //weight: 1
        $x_1_3 = "Teardroid" ascii //weight: 1
        $x_1_4 = "webhook.site/de799e0c-da90-4438-af38-7227c1cfb6c2" ascii //weight: 1
        $x_1_5 = "runshell" ascii //weight: 1
        $x_1_6 = "makecall" ascii //weight: 1
        $x_1_7 = "getcontact" ascii //weight: 1
        $x_1_8 = "getsms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

