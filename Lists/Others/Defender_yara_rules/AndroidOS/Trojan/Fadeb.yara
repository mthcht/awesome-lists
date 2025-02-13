rule Trojan_AndroidOS_Fadeb_A_2147852273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fadeb.A"
        threat_id = "2147852273"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fadeb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Installer exucte error:----apkFilePath:" ascii //weight: 1
        $x_1_2 = "failedStatUrls" ascii //weight: 1
        $x_1_3 = "mgm9ms7691" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

