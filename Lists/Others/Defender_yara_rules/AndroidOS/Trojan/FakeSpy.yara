rule Trojan_AndroidOS_Fakespy_A_2147797799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakespy.A"
        threat_id = "2147797799"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "45006" ascii //weight: 2
        $x_2_2 = "/servlet/UploadLog" ascii //weight: 2
        $x_2_3 = "/servlet/ContactsUpload" ascii //weight: 2
        $x_2_4 = "shit:" ascii //weight: 2
        $x_2_5 = "http://www.sagawa-exp.co.jp/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

