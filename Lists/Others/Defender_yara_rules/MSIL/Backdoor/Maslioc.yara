rule Backdoor_MSIL_Maslioc_A_2147688947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Maslioc.A"
        threat_id = "2147688947"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Maslioc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|ddos_on" wide //weight: 1
        $x_1_2 = "|DoScreen" wide //weight: 1
        $x_1_3 = "|HardwareBoot" wide //weight: 1
        $x_1_4 = "|Polizei_ON" wide //weight: 1
        $x_1_5 = "|Firewall_OFF" wide //weight: 1
        $x_1_6 = "AddToAutorun" ascii //weight: 1
        $x_1_7 = "Stresser_ON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

