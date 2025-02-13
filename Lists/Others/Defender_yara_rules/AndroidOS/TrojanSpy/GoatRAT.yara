rule TrojanSpy_AndroidOS_GoatRAT_B_2147842884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GoatRAT.B"
        threat_id = "2147842884"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GoatRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "api.goatrat.com:3008/users/" ascii //weight: 2
        $x_2_2 = "ScreenSharingService got command:" ascii //weight: 2
        $x_1_3 = "GoatRat.com - Remote Access" ascii //weight: 1
        $x_1_4 = "Lcom/goatmw/communication/Server" ascii //weight: 1
        $x_1_5 = "goatRat - remote access" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

