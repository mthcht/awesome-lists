rule Ransom_MSIL_ArtemonCrypt_PA_2147775128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ArtemonCrypt.PA!MTB"
        threat_id = "2147775128"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Artemon.txt" wide //weight: 1
        $x_1_2 = "Your files encrypted" wide //weight: 1
        $x_1_3 = "TrojanRansomArtemonRUS.txt" wide //weight: 1
        $x_1_4 = "\\exeexeexe1.ArtemonTrojan" wide //weight: 1
        $x_1_5 = "Hello! You victim on ARTEMON RANSOMWARE!" wide //weight: 1
        $x_1_6 = "Trojan.Ransom.Artemon.A RANSOMWARE! 2021" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

