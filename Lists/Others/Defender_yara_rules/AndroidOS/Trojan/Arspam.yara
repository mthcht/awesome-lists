rule Trojan_AndroidOS_Arspam_A_2147652608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arspam.A"
        threat_id = "2147652608"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arspam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BICIreportAR.pdf" ascii //weight: 1
        $x_1_2 = "alArabiyyah.java" ascii //weight: 1
        $x_1_3 = "sileria/alsalah" ascii //weight: 1
        $x_1_4 = "Attaching GPS listener..." ascii //weight: 1
        $x_1_5 = "alsalah.sileria.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

