rule Trojan_MSIL_Gillver_A_2147649725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gillver.A"
        threat_id = "2147649725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gillver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 75 00 6e 00 50 00 45 00 ?? ?? 49 00 6e 00 6a 00 65 00 63 00 74 00 50 00 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = "PolyDeCrypt" ascii //weight: 1
        $x_1_3 = "trolololol" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

