rule TrojanSpy_AndroidOS_Bankbot_A_2147798779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bankbot.A"
        threat_id = "2147798779"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bankbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sharked.db" ascii //weight: 1
        $x_1_2 = "/aaBootReceiver;" ascii //weight: 1
        $x_1_3 = {d8 00 00 ff 3a 00 1b 00 6e 20 ?? 85 04 00 0a 02 d8 03 00 ff df 02 02 ?? 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 ?? 85 34 00 0a 02 df 02 02 ?? 8e 22 50 02 01 03}  //weight: 1, accuracy: Low
        $x_1_4 = "Theme_Sharked1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

