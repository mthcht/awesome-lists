rule Trojan_MSIL_Loksec_A_2147691473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loksec.A"
        threat_id = "2147691473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loksec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 25 00 ?? ?? 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Macrovision Security Driver" wide //weight: 1
        $x_1_3 = {5c 00 52 00 75 00 6e 00 ?? ?? 73 00 65 00 63 00 64 00 72 00 76 00}  //weight: 1, accuracy: Low
        $x_1_4 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 45 00 78 00 70 00 65 00 72 00 69 00 65 00 6e 00 63 00 65 00 [0-4] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 72 00 6f 00 66 00 53 00 76 00 63 00 [0-5] 41 00 70 00 70 00 44 00 61 00 74 00 61 00 25 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 00 65 00 63 00 64 00 72 00 76 00 [0-5] 25 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 25 00}  //weight: 1, accuracy: Low
        $x_1_7 = "Microsoft\\secdrv.exe" ascii //weight: 1
        $x_1_8 = "AeLookupSvi\\obj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

