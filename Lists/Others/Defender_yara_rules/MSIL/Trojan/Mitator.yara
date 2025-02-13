rule Trojan_MSIL_Mitator_A_2147708041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mitator.A"
        threat_id = "2147708041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mitator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "InstallHKCU" ascii //weight: 2
        $x_2_2 = "DisableUAC" ascii //weight: 2
        $x_1_3 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_4 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

