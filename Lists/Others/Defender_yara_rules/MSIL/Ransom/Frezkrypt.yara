rule Ransom_MSIL_Frezkrypt_A_2147726469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Frezkrypt.A"
        threat_id = "2147726469"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Frezkrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "J:\\Programs\\JF Ransomware\\JF Ransomware\\obj\\Debug\\JF Ransomware.pdb" ascii //weight: 2
        $x_2_2 = "JF Ransomware" ascii //weight: 2
        $x_2_3 = "JF_Ransomware" ascii //weight: 2
        $x_2_4 = "All of your files have been encrypted!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

