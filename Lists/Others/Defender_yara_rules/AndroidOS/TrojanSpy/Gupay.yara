rule TrojanSpy_AndroidOS_Gupay_A_2147838684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gupay.A!MTB"
        threat_id = "2147838684"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gupay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getAndSendData" ascii //weight: 1
        $x_1_2 = "sendPayData" ascii //weight: 1
        $x_1_3 = "deleteAPP" ascii //weight: 1
        $x_1_4 = "isPhoneCalling" ascii //weight: 1
        $x_1_5 = "wasScreenOn" ascii //weight: 1
        $x_1_6 = "sendPostRequest" ascii //weight: 1
        $x_5_7 = "mSpY" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

