rule Worm_MSIL_Najm_A_2147779586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Najm.A!MTB"
        threat_id = "2147779586"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Najm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 0b 16 0c 38 86 ?? ?? ?? 07 08 9a 0d 00 09 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 2c 0c 11 04 6f ?? ?? ?? 0a 18 fe 01 2b 01 16 13 05 11 05 2c 53 00 11 04}  //weight: 10, accuracy: Low
        $x_5_2 = "Najm" ascii //weight: 5
        $x_4_3 = "Najm_info" ascii //weight: 4
        $x_3_4 = "frm_faleya_aama" ascii //weight: 3
        $x_3_5 = "frm_jawanan" ascii //weight: 3
        $x_3_6 = "frm_nasharat" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

