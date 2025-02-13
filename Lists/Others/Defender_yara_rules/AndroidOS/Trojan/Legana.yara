rule Trojan_AndroidOS_Legana_A_2147650707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Legana.A"
        threat_id = "2147650707"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Legana"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stak_yExy-eLt!Pw" ascii //weight: 1
        $x_1_2 = {cc af 4b 1b 0b 94 7a 79 eb 4a 51 49 4c 85 49 8c 6d d6 29 25 74 c0 23 b2 fa a6 7b 50 2a 0d 38 25}  //weight: 1, accuracy: High
        $x_1_3 = "safesys" ascii //weight: 1
        $x_1_4 = "etc/.dhcpcd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

