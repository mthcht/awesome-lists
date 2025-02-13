rule Ransom_MSIL_CryptInject_2147749900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptInject!MSR"
        threat_id = "2147749900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your data is now encrypted, pay ransom!" wide //weight: 2
        $x_1_2 = "Encryption warning" wide //weight: 1
        $x_1_3 = "Ransomware.exe" ascii //weight: 1
        $x_1_4 = "Debug\\Ransomware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

