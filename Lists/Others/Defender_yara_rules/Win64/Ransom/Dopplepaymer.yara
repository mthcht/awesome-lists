rule Ransom_Win64_Dopplepaymer_C_2147745558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Dopplepaymer.C"
        threat_id = "2147745558"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " -Command " wide //weight: 1
        $x_1_2 = ".DownloadFile('http://eltrade.ro/lucru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Dopplepaymer_A_2147745780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Dopplepaymer.A"
        threat_id = "2147745780"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 89 c8 32 c9 44 89 c2 fe c1 d1 ea 89 d0 35 20 83 b8 ed 41 f7 c0 01 00 00 00 41 89 c0 44 0f 44 c2 80 f9 08 7c df 47 89 04 8a 49 ff c1 49 81 f9 00 01 00 00 7c ca}  //weight: 1, accuracy: High
        $x_1_2 = {41 89 c2 ff ca 45 0f b6 08 4d 33 d1 45 0f b6 da 49 ff c0 c1 e8 08 42 33 04 99 83 fa ff 75 e1 4c 89 45 18 f7 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

