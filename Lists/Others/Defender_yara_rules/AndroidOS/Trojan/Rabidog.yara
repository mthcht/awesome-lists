rule Trojan_AndroidOS_Rabidog_A_2147648520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rabidog.A"
        threat_id = "2147648520"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rabidog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I take pleasure in hurting small animals," ascii //weight: 1
        $x_1_2 = "contact_id =" ascii //weight: 1
        $x_1_3 = "/dogbite/Rabies" ascii //weight: 1
        $x_1_4 = "has_phone_number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

