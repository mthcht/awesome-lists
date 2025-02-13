rule TrojanSpy_AndroidOS_Boogr_B_2147816009_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Boogr.B!MTB"
        threat_id = "2147816009"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "carca.shiprist.app" ascii //weight: 5
        $x_5_2 = "chenna.co.in" ascii //weight: 5
        $x_1_3 = "call_log/calls" ascii //weight: 1
        $x_1_4 = "contactslist" ascii //weight: 1
        $x_1_5 = "canGetLocation" ascii //weight: 1
        $x_1_6 = "sIMInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

