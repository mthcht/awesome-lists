rule PWS_MSIL_Cosratu_A_2147724989_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Cosratu.A!bit"
        threat_id = "2147724989"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cosratu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 02 07 6f 09 00 00 0a 03 07 03 6f 0a 00 00 0a 5d 6f 09 00 00 0a 61 d1 6f 0b 00 00 0a 26 07 17 58 0b}  //weight: 1, accuracy: High
        $x_1_2 = "costura.decrypt.dll.compressed" ascii //weight: 1
        $x_1_3 = {00 49 56 69 63 74 69 6d 43 61 6c 6c 62 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 65 6e 64 55 72 6c 41 6e 64 45 78 65 63 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 42 69 74 63 6f 69 6e 57 61 6c 6c 65 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 43 72 65 61 74 65 43 6f 6d 70 61 74 69 62 6c 65 42 69 74 6d 61 70 00 46 72 6f 6d 48 62 69 74 6d 61 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

