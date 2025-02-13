rule Ransom_MSIL_Lazagcrypt_2147725312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lazagcrypt"
        threat_id = "2147725312"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazagcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "We have received your payment and will now proceed to decrypt your files." wide //weight: 2
        $x_2_2 = "If you fail to comply within 36h, the ransom will be raised. You have been warned." wide //weight: 2
        $x_2_3 = "wfmmp8@sigaint.org" wide //weight: 2
        $x_2_4 = "e:\\Projects\\brc\\brc\\obj\\x86\\Release\\brc.pdb" ascii //weight: 2
        $x_2_5 = "brc.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

