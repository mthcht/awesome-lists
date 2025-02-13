rule Ransom_Win64_EpsilonRed_A_2147930889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/EpsilonRed.A"
        threat_id = "2147930889"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "EpsilonRed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FilesWithExtensions.func1" ascii //weight: 1
        $x_1_2 = "main.myFileW" ascii //weight: 1
        $x_1_3 = "main.ePL" ascii //weight: 1
        $x_1_4 = "crypto/aes.expandKeyGo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

