rule Trojan_MSIL_Survins_A_2147696411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Survins.A"
        threat_id = "2147696411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Survins"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 6b 6e 6f 33 00 4f 6b 6e 6f 34 00 4f 6b 6e 6f 35 00 55 73 74 61 77 69 65 6e 69 61 00}  //weight: 1, accuracy: High
        $x_1_2 = {4f 00 6b 00 6e 00 6f 00 31 00 [0-32] 20 00 2d 00 20 00 53 00 65 00 74 00 75 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Instalator\\obj\\x86\\Debug\\" ascii //weight: 1
        $x_1_4 = "by clicking a button \"Download Key\"" wide //weight: 1
        $x_1_5 = "http://tinyfileshost.com/download/" wide //weight: 1
        $x_1_6 = {4f 00 6b 00 6e 00 6f 00 31 00 [0-2] 20 00 2d 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 53 00 68 00 69 00 65 00 6c 00 64 00 20 00 57 00 69 00 7a 00 61 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6b 00 6c 00 69 00 6b 00 61 00 6a 00 [0-2] 63 00 20 00 6e 00 61 00 20 00 70 00 72 00 7a 00 79 00 63 00 69 00 73 00 6b 00 20 00 50 00 6f 00 62 00 69 00 65 00 72 00 7a 00 20 00 4b 00 6c 00 75 00 63 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_8 = "http://klikwplik.pl/" wide //weight: 1
        $x_1_9 = "http://pushcloud.org/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

