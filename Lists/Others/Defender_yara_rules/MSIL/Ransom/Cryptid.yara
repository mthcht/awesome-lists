rule Ransom_MSIL_Cryptid_2147725299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptid"
        threat_id = "2147725299"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your files are encrypted." wide //weight: 2
        $x_2_2 = "#DECRYPT MY FILES#.html" wide //weight: 2
        $x_2_3 = "paradise@all-ransomware.info" wide //weight: 2
        $x_2_4 = "Paradise Ransomware Team!" wide //weight: 2
        $x_2_5 = "You have to pay for decryption in Bitcoins." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

