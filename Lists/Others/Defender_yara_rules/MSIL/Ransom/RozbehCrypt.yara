rule Ransom_MSIL_RozbehCrypt_PA_2147808327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RozbehCrypt.PA!MTB"
        threat_id = "2147808327"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RozbehCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOVE-LETTER-FOR-YOU.TXT.vbs" wide //weight: 1
        $x_1_2 = "All your Files has been Encrypted by Rozbeh Ransomware" wide //weight: 1
        $x_1_3 = "\\EvilNominatus.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

