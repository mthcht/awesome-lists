rule Trojan_AndroidOS_Defendr_A_2147682306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Defendr.A"
        threat_id = "2147682306"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Defendr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 73 65 74 69 6e 67 3a 20 ?? ?? ?? ?? 52 65 74 61 69 6e 69 6e 67 3a 20 ?? ?? ?? ?? 53 74 61 72 74 69 6e 67 3a 20 ?? ?? ?? ?? 53 74 6f 70 70 69 6e 67 3a 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/html/billing/" ascii //weight: 1
        $x_1_3 = "android_version" ascii //weight: 1
        $x_1_4 = "com/android/defender/" ascii //weight: 1
        $x_1_5 = "defender/androiddefender/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

