rule Trojan_AndroidOS_Sharkspy_A_2147833997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Sharkspy.A"
        threat_id = "2147833997"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Sharkspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "x_RandomUser" ascii //weight: 2
        $x_2_2 = "com.example.autoconnect" ascii //weight: 2
        $x_2_3 = "|!|False|!|False|!|False|!|False|!|7.0.0.10|!|" ascii //weight: 2
        $x_2_4 = "typeOfSMS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

