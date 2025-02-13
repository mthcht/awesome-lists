rule TrojanSpy_AndroidOS_MazarBOT_A_2147780686_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/MazarBOT.A!MTB"
        threat_id = "2147780686"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "MazarBOT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "setOnCreditCardTypeChangedListener" ascii //weight: 2
        $x_2_2 = "exts.whats.wakeup" ascii //weight: 2
        $x_2_3 = "hard reset" ascii //weight: 2
        $x_1_4 = "/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto" ascii //weight: 1
        $x_1_5 = "REPORT_CARD_DATA" ascii //weight: 1
        $x_1_6 = "sendData" ascii //weight: 1
        $x_1_7 = "INTERCEPTING_ENABLED" ascii //weight: 1
        $x_1_8 = "getRunningAppProcessInfo" ascii //weight: 1
        $x_1_9 = "kill call" ascii //weight: 1
        $x_1_10 = "getActiveNetworkInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

