rule Trojan_AndroidOS_GGSmart_A_2147653743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GGSmart.A"
        threat_id = "2147653743"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GGSmart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/system/app/smartclient.apk" ascii //weight: 1
        $x_1_2 = "fake_app_package_name" ascii //weight: 1
        $x_1_3 = "it's not 2.0" ascii //weight: 1
        $x_1_4 = "resources/commons/shells.zip" ascii //weight: 1
        $x_1_5 = {65 78 70 6c 6f 69 74 00 07 69 6e 73 74 61 6c 6c 00 0a 63 68 6d 6f 64 20 37 37 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

