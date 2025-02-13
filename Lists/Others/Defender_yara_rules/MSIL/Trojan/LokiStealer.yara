rule Trojan_MSIL_LokiStealer_A_2147742274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiStealer.A"
        threat_id = "2147742274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_2 = {4c 6f 6b 69 5c [0-16] 5c [0-16] 5c 6c 6f 6b 69 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "[===================== Loki Stealer ============================]" wide //weight: 1
        $x_1_4 = "\\info.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

