rule Trojan_MSIL_CryptDownloader_A_2147906401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptDownloader.A"
        threat_id = "2147906401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptDownloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65 00 6f 70 5f 49 6e 65 71 75 61 6c 69 74 79 ?? 45 78 69 74 00 47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 6d 73 74 65 72 46 75 6e 63 00 64 61 74 61 74 68 72 65 61 64 ?? 64 65 63 52 00 62 79 74 65 73 54 6f 42 65 44 65 63 72 79 70 74 65 64 00 70 61 73 73 77 6f 72 64 42 79 74 65 73 00 52 75 6e 6e 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

