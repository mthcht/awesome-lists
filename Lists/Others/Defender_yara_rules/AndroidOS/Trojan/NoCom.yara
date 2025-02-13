rule Trojan_AndroidOS_NoCom_A_2147656721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/NoCom.A"
        threat_id = "2147656721"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "NoCom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IPaddres" ascii //weight: 1
        $x_1_2 = "SecurityUpdateService.java" ascii //weight: 1
        $x_1_3 = "newReservServer" ascii //weight: 1
        $x_1_4 = "openRawResource" ascii //weight: 1
        $x_1_5 = "Security/Update/SecurityUpdateService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

