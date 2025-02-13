rule Trojan_MSIL_Mobazug_A_2147688074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mobazug.A"
        threat_id = "2147688074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mobazug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 63 61 6e 65 64 46 69 6c 65 4e 75 6d 62 65 72 00 76 69 72 75 73 46 6f 75 6e 64 00 68 65 61 6e 46 6f 75 6e 64}  //weight: 1, accuracy: High
        $x_1_2 = "{0} Virus Found | {1} ;" wide //weight: 1
        $x_1_3 = {68 00 65 00 61 00 6e 00 [0-2] 73 00 63 00 61 00 6e 00 74 00 79 00 70 00 65 00 [0-2] 73 00 65 00 78 00 [0-2] 70 00 6f 00 72 00 6e 00 [0-2] 61 00 64 00 75 00 6c 00 74 00 [0-2] 73 00 61 00 66 00 65 00 [0-2] 6e 00 6f 00 72 00 6d 00 61 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/Kaspersky;component/MainPage.xaml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

