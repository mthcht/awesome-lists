rule Ransom_MSIL_Hyptkript_A_2147716794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hyptkript.A"
        threat_id = "2147716794"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hyptkript"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Files was encrypted!" wide //weight: 1
        $x_1_2 = "Do you decrypt your Files" wide //weight: 1
        $x_2_3 = "1463453536_vodafone" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Hyptkript_A_2147716946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hyptkript.A!!Hyptkript.gen!A"
        threat_id = "2147716946"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hyptkript"
        severity = "Critical"
        info = "Hyptkript: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Files was encrypted!" wide //weight: 1
        $x_1_2 = "Do you decrypt your Files" wide //weight: 1
        $x_2_3 = "1463453536_vodafone" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

