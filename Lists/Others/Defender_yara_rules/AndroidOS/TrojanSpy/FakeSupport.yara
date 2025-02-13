rule TrojanSpy_AndroidOS_FakeSupport_A_2147812362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeSupport.A!MTB"
        threat_id = "2147812362"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeSupport"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/example/complaintregisters/ComplainData" ascii //weight: 1
        $x_1_2 = "getDebitCardNumber" ascii //weight: 1
        $x_1_3 = "getAtmPin" ascii //weight: 1
        $x_1_4 = "getTransactionPassword" ascii //weight: 1
        $x_1_5 = "www.complaintsregisterquery.com" ascii //weight: 1
        $x_1_6 = "getAllSms" ascii //weight: 1
        $x_1_7 = "getAccountNumber" ascii //weight: 1
        $x_1_8 = "/msgstore?task=savemsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

