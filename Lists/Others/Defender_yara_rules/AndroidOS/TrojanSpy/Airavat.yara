rule TrojanSpy_AndroidOS_Airavat_A_2147826592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Airavat.A"
        threat_id = "2147826592"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Airavat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_changewall" ascii //weight: 1
        $x_1_2 = "_dmpcal" ascii //weight: 1
        $x_1_3 = "_dmpcon" ascii //weight: 1
        $x_1_4 = "_dmpsm" ascii //weight: 1
        $x_1_5 = "_palysmudic" ascii //weight: 1
        $x_1_6 = "_setrespo" ascii //weight: 1
        $x_1_7 = "_setpres" ascii //weight: 1
        $x_1_8 = "_snotiow" ascii //weight: 1
        $x_1_9 = "_sudoapt" ascii //weight: 1
        $x_1_10 = "_ttsdev" ascii //weight: 1
        $x_1_11 = "_voicere" ascii //weight: 1
        $x_1_12 = "_setpres2" ascii //weight: 1
        $x_1_13 = "_phidatsu" ascii //weight: 1
        $x_1_14 = "_pihtest" ascii //weight: 1
        $x_1_15 = "_remicbje" ascii //weight: 1
        $x_1_16 = "shownotiss" ascii //weight: 1
        $x_1_17 = "openweburi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

