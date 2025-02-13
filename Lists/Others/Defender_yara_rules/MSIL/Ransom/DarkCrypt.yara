rule Ransom_MSIL_DarkCrypt_PAA_2147797958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DarkCrypt.PAA!MTB"
        threat_id = "2147797958"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransomware" ascii //weight: 1
        $x_1_2 = "Win32_ShadowCopy" wide //weight: 1
        $x_1_3 = "\\DarkCrypt_Massage.txt" wide //weight: 1
        $x_1_4 = "Important Things Are Encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

