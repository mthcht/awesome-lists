rule Trojan_MSIL_Drokbk_A_2147820259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Drokbk.A!dha"
        threat_id = "2147820259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Drokbk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\SoftwareDistribution" wide //weight: 1
        $x_1_2 = "c:\\users\\public\\pla" wide //weight: 1
        $x_1_3 = "Session Manager Service" wide //weight: 1
        $x_1_4 = "Provides Kernel Compatibility With User Session-Management Service." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Drokbk_B_2147820260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Drokbk.B!dha"
        threat_id = "2147820260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Drokbk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://api.github.com/search/repositories?q=mainrepositorytogetavailablechanse" wide //weight: 1
        $x_1_2 = "c:\\programdata\\Interop Services" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

