rule Trojan_MSIL_Ribaj_A_2147727581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ribaj.A"
        threat_id = "2147727581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ribaj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jabir.b" wide //weight: 1
        $x_1_2 = "h.exe" wide //weight: 1
        $x_1_3 = "111111" wide //weight: 1
        $x_1_4 = "/target:winexe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

