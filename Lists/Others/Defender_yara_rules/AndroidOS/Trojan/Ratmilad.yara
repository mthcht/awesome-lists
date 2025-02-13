rule Trojan_AndroidOS_Ratmilad_A_2147833639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ratmilad.A"
        threat_id = "2147833639"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ratmilad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SEND_LOG_MESSAGE_TEXT" ascii //weight: 2
        $x_2_2 = "GRANTED_PERMISSIONS_LIST" ascii //weight: 2
        $x_2_3 = "SEND_SELF_DEFENCE_DATA" ascii //weight: 2
        $x_2_4 = "recursiveDownload" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

