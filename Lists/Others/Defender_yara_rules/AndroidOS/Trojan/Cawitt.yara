rule Trojan_AndroidOS_Cawitt_A_2147658062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Cawitt.A"
        threat_id = "2147658062"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Cawitt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/carbontetraiodide" ascii //weight: 1
        $x_1_2 = "orika" ascii //weight: 1
        $x_1_3 = "{accidentaly}" ascii //weight: 1
        $x_1_4 = "{troll}" ascii //weight: 1
        $x_1_5 = ".qipim.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

