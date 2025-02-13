rule Trojan_MSIL_UrsuPow_AA_2147743060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/UrsuPow.AA"
        threat_id = "2147743060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UrsuPow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 74 00 79 00 6c 00 65 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 26 00 7b 00 24 00 74 00 3d 00 27 00 23 00 23 00 69 00 65 00 78 00 23 00 40 00 28 00 6e 00 65 00 77 00 23 00 2d 00 23 00 6f 00 62 00 23 00 6a 00 65 00 63 00 23 00 74 00 20 00 4e 00 23 00 23 00 65 00 74 00 23 00 2e 00 57 00 23 00 65 00 62 00 23 00 43 00 6c 00 23 00 69 00 65 00 23 00 6e 00 74 00 23 00 29 00 2e 00 23 00 55 00 70 00 23 00 6c 00 6f 00 61 00 23 00 64 00 23 00 53 00 74 00 23 00 72 00 69 00 23 00 6e 00 67 00 28 00 23 00 27 00 27 00 68 00 23 00 74 00 23 00 74 00 70}  //weight: 1, accuracy: High
        $x_1_2 = "choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

