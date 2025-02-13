rule Trojan_AndroidOS_Carbonsteal_B_2147797798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Carbonsteal.B"
        threat_id = "2147797798"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Carbonsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chmod 777 /system/app/GoogleMail.apk" ascii //weight: 2
        $x_2_2 = "Ak47gdrerth" ascii //weight: 2
        $x_2_3 = "/ainfodb.db" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

