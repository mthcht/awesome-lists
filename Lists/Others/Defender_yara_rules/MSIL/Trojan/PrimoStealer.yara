rule Trojan_MSIL_PrimoStealer_AMTB_2147980942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrimoStealer!AMTB"
        threat_id = "2147980942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrimoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PRIMOSTEALER" ascii //weight: 2
        $x_2_2 = "primo_err.txt" ascii //weight: 2
        $x_1_3 = "Sent via webhook" ascii //weight: 1
        $x_1_4 = "primo_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

