rule TrojanSpy_AndroidOS_Nyleaker_B_2147794010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Nyleaker.B"
        threat_id = "2147794010"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Nyleaker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "setDeliveryReceiverPhone" ascii //weight: 2
        $x_1_2 = "SetIconReceiver" ascii //weight: 1
        $x_1_3 = "FingerSecurityScanner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

