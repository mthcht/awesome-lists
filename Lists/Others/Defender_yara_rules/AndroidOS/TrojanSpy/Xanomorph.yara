rule TrojanSpy_AndroidOS_Xanomorph_A_2147813544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Xanomorph.A"
        threat_id = "2147813544"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Xanomorph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "accessRainbowServer: send message" ascii //weight: 2
        $x_2_2 = "IDynamicLoader" ascii //weight: 2
        $x_2_3 = "checkAvailability: start to access config server" ascii //weight: 2
        $x_1_4 = "penaltyriver" ascii //weight: 1
        $x_1_5 = "twelvemarriage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

