rule TrojanSpy_AndroidOS_SecCert_A_2147782419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SecCert.A!MTB"
        threat_id = "2147782419"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SecCert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "start_sms_forwarding" ascii //weight: 1
        $x_1_2 = "USSDDumbExtendedNetwork" ascii //weight: 1
        $x_1_3 = "numbers_to_sms_divert" ascii //weight: 1
        $x_1_4 = "numbers_to_call_block" ascii //weight: 1
        $x_1_5 = {4c 63 6f 6d [0-38] 50 68 6f 6e 65 43 61 6c 6c 52 65 63 65 69 76 65 72}  //weight: 1, accuracy: Low
        $x_1_6 = "sender_phone_number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

