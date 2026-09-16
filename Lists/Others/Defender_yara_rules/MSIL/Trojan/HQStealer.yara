rule Trojan_MSIL_HQStealer_AMTB_2147978241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/HQStealer!AMTB"
        threat_id = "2147978241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HQStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 51 53 74 65 61 6c 65 72 2e 44 69 73 63 6f 72 64 47 72 61 62 62 65 72 2b 3c [0-31] 3e}  //weight: 2, accuracy: Low
        $x_2_2 = {48 51 53 74 65 61 6c 65 72 2e 44 69 73 63 6f 72 64 41 70 69 43 6c 69 65 6e 74 2b 3c [0-31] 3e}  //weight: 2, accuracy: Low
        $x_1_3 = "HQStealer.Program" ascii //weight: 1
        $x_1_4 = "HQStealer.Payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

