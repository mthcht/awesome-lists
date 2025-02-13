rule TrojanSpy_AndroidOS_Mekir_B_2147852648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mekir.B!MTB"
        threat_id = "2147852648"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mekir"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendTextMessage" ascii //weight: 1
        $x_5_2 = "Lcom/android/deviceinfo/listener" ascii //weight: 5
        $x_1_3 = "removeActiveAdmin" ascii //weight: 1
        $x_1_4 = "lockNow" ascii //weight: 1
        $x_1_5 = ".apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

