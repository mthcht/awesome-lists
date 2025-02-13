rule TrojanSpy_AndroidOS_GigaBudRAT_A_2147839459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GigaBudRAT.A!MTB"
        threat_id = "2147839459"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GigaBudRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x/user-bank-pwd" ascii //weight: 1
        $x_1_2 = "bankImg" ascii //weight: 1
        $x_1_3 = "SendMsgInfo" ascii //weight: 1
        $x_1_4 = "BankCardInfo" ascii //weight: 1
        $x_1_5 = "onReceiverCommendaction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

