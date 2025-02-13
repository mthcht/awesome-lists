rule Trojan_AndroidOS_Marcher_A_2147896812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Marcher.A"
        threat_id = "2147896812"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Marcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-!ps!qbsfou!je!1y" ascii //weight: 2
        $x_2_2 = "Bdujwf!Gsbhnfout!jo!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Marcher_B_2147896813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Marcher.B"
        threat_id = "2147896813"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Marcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmVudFNUT1AmJiY=" ascii //weight: 1
        $x_1_2 = "WebApps Service started" ascii //weight: 1
        $x_1_3 = "YXWLzZuduxxoKxZe" ascii //weight: 1
        $x_1_4 = "YXlsYGIoHhoiqkJK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Marcher_FT_2147927144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Marcher.FT"
        threat_id = "2147927144"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Marcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CustomCardNumber_inputType" ascii //weight: 1
        $x_1_2 = "Please submit your Verifed buy MasterCard Password" ascii //weight: 1
        $x_1_3 = "sms_hook_no_api" ascii //weight: 1
        $x_1_4 = "QERFTEVURQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

