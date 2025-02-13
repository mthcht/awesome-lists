rule Trojan_AndroidOS_Anatsa_A_2147807201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Anatsa.A"
        threat_id = "2147807201"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Anatsa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FoolishUpdateService" ascii //weight: 1
        $x_1_2 = "ApkDownloaderImpl" ascii //weight: 1
        $x_1_3 = "update_came" ascii //weight: 1
        $x_1_4 = "1.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

