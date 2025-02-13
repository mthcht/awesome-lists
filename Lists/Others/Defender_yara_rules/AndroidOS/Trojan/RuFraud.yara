rule Trojan_AndroidOS_RuFraud_A_2147652318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RuFraud.A"
        threat_id = "2147652318"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RuFraud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "91.213.175.148/app" ascii //weight: 1
        $x_1_2 = "Downloading file..." ascii //weight: 1
        $x_1_3 = "E273FED8415F7B1D8CFEAC80A96CFF46" ascii //weight: 1
        $x_1_4 = "RuleActivity$downloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

