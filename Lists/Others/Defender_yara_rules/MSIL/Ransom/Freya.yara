rule Ransom_MSIL_Freya_RPG_2147830263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Freya.RPG!MTB"
        threat_id = "2147830263"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Freya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Freya Ransomware" ascii //weight: 1
        $x_1_2 = "ReadMe.txt" wide //weight: 1
        $x_1_3 = ".Lewd" wide //weight: 1
        $x_1_4 = "Key.txt" wide //weight: 1
        $x_1_5 = "LewdDecryptor.exe" wide //weight: 1
        $x_1_6 = "YourAttackPath.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

