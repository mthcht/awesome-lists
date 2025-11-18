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

rule Trojan_MSIL_Ribaj_ARI_2147957638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ribaj.ARI!MTB"
        threat_id = "2147957638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ribaj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 13 0d 16 13 0e 2b 23 11 0d 11 0e 9a 13 04 7e ?? 00 00 04 1b 33 02 de 1a 11 04 28 ?? 00 00 06 de 03 26 de 00 11 0e 17 58 13 0e 11 0e 11 0d 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

