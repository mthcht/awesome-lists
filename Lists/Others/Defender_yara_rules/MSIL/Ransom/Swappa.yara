rule Ransom_MSIL_Swappa_A_2147689076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Swappa.A"
        threat_id = "2147689076"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Swappa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "dragoncrypt" ascii //weight: 5
        $x_5_2 = "\\encryptedFiles.txt" wide //weight: 5
        $x_5_3 = "\\tempfolderdragoncrypt" wide //weight: 5
        $x_1_4 = "SwaftyKappa" wide //weight: 1
        $x_1_5 = "lol u so leet :D" wide //weight: 1
        $x_1_6 = "\\k.key" wide //weight: 1
        $x_1_7 = "decryptservice@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Swappa_B_2147694716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Swappa.B"
        threat_id = "2147694716"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Swappa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\encryptedFiles.txt" wide //weight: 1
        $x_1_2 = "\\tempfolderdragoncrypt" wide //weight: 1
        $x_1_3 = "Otkupnina sada iznosi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

