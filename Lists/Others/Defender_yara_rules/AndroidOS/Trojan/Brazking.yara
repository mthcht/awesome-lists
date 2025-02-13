rule Trojan_AndroidOS_Brazking_A_2147813140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Brazking.A"
        threat_id = "2147813140"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Brazking"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Certificate chain too long" ascii //weight: 2
        $x_2_2 = "Acessibilidade" ascii //weight: 2
        $x_2_3 = "dumpa@" ascii //weight: 2
        $x_2_4 = "performGlobalAction" ascii //weight: 2
        $x_2_5 = "FECHA_TRAVA" ascii //weight: 2
        $x_2_6 = "@fecha?key=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

