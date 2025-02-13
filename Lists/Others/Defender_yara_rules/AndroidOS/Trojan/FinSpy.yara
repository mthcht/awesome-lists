rule Trojan_AndroidOS_FinSpy_B_2147783397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FinSpy.B"
        threat_id = "2147783397"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FinSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/eventbased/ReceiverService" ascii //weight: 1
        $x_1_2 = "Lorg/xmlpush/v3/EventBasedService" ascii //weight: 1
        $x_1_3 = {48 02 05 00 21 43 94 03 00 03 48 03 04 03 b7 32 8d 22 4f 02 01 00 d8 00 00 01 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

