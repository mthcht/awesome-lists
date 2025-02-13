rule Trojan_AndroidOS_Drinik_A_2147794144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Drinik.A"
        threat_id = "2147794144"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Drinik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chujxxllif" ascii //weight: 2
        $x_2_2 = "eaoomxhltif" ascii //weight: 2
        $x_1_3 = "zzcxvuddi" ascii //weight: 1
        $x_1_4 = "bjomxalkl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Drinik_B_2147813066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Drinik.B"
        threat_id = "2147813066"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Drinik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "104 116 116 112 58 47 47 49 57 56 46 49 50 46 49 48 55 46 49 51 47 105 97 115 101 114 118 101 114 46 112 104 112" ascii //weight: 1
        $x_1_2 = "65 99 99 83 101 114 118 58 67 111 110 110 101 99 116 87 76" ascii //weight: 1
        $x_1_3 = "105 110 115 101 114 116 83 101 114 118 101 114 67 77 68" ascii //weight: 1
        $x_1_4 = "68 111 99 115 85 112 108 111 97 100 32 115 117 99 99 101 115 115 102 117 108" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

