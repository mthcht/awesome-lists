rule Trojan_MSIL_Boldens_A_2147706813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Boldens.A"
        threat_id = "2147706813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Boldens"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HRESULT 0xc8000222" wide //weight: 1
        $x_1_2 = {5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 5c 00 ?? ?? 5c 00 ?? ?? 4e 00 61 00 6d 00 65 00 53 00 65 00 72 00 76 00 65 00 72 00 [0-32] 2c 00 38 00 2e 00 38 00 2e 00 38 00 2e 00 38 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 00 4f 00 53 00 54 00 ?? ?? 6e 00 61 00 6d 00 65 00 3d 00 4a 00 69 00 6d 00 26 00 61 00 67 00 65 00 3d 00 32 00 37 00 26 00 70 00 69 00 7a 00 7a 00 61 00 3d 00 73 00 75 00 61 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

