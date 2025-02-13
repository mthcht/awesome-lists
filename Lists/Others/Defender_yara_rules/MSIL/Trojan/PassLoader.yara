rule Trojan_MSIL_PassLoader_B_2147780113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PassLoader.B"
        threat_id = "2147780113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PassLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Provider=SQLNCLI11" wide //weight: 5
        $x_5_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 74 00 61 00 74 00 65 00 2d 00 [0-48] 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00}  //weight: 5, accuracy: Low
        $x_1_3 = "SELECT ProxyServer, ProxyUserName, ProxyPassword FROM" wide //weight: 1
        $x_1_4 = {4b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 41 67 65 6e 74 2e 64 6c 6c 00 49 73 44 42 4e 75 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 50 61 73 73 77 6f 72 64 73 4c 69 73 74 00 47 65 74 53 65 72 76 69 63 65 73 4c 69 73 74 00 47 65 74 50 72 6f 63 65 73 73 4c 69 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

