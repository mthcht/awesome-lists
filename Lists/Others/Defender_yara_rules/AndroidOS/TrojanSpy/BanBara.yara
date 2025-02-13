rule TrojanSpy_AndroidOS_BanBara_A_2147843496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/BanBara.A!MTB"
        threat_id = "2147843496"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "BanBara"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bankCreds$delegate" ascii //weight: 1
        $x_1_2 = "PaymentHijark" ascii //weight: 1
        $x_1_3 = "mobile/Upload/Collected" ascii //weight: 1
        $x_1_4 = "brazilBankSwitch$delegate" ascii //weight: 1
        $x_1_5 = "getAimedSms" ascii //weight: 1
        $x_1_6 = "getBankSetting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

