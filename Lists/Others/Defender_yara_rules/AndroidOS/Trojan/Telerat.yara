rule Trojan_AndroidOS_Telerat_C_2147795504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Telerat.C"
        threat_id = "2147795504"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Telerat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b4a.example.botrat" ascii //weight: 1
        $x_1_2 = "_a_picturetaken" ascii //weight: 1
        $x_1_3 = "_smsins_messagesent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

