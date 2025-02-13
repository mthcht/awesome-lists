rule Ransom_MSIL_Mrynimal_2147729796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mrynimal"
        threat_id = "2147729796"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mrynimal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Minotaur.exe" ascii //weight: 10
        $x_10_2 = " minotaur@420blaze.it" ascii //weight: 10
        $x_10_3 = "ALL YOUR FILES ARE ENCRYPTED BY (MINOTAUR) RANSOMWARE!" ascii //weight: 10
        $x_5_4 = "FOR DECRYPT YOUR FILES NEED TO PAY US A (0.125 BTC)!" ascii //weight: 5
        $x_5_5 = "SEND YOUR (KEY) TO OUR E-MAIL FOR SUPPORT!" ascii //weight: 5
        $x_5_6 = "How To Decrypt Files.txt" ascii //weight: 5
        $x_30_7 = {50 72 69 76 61 74 65 5c 4d 69 6e 6f 74 61 75 72 5c 4d 69 6e 6f 74 61 75 72 [0-24] 5c 4d 69 6e 6f 74 61 75 72 2e 70 64 62}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_30_*) and 2 of ($x_5_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

