rule Ransom_MSIL_Gorf_2147725282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Gorf"
        threat_id = "2147725282"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gorf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "frog.exe" ascii //weight: 2
        $x_2_2 = "d:\\project_mini\\mwave\\frog\\frog\\obj\\Release\\frog.pdb" ascii //weight: 2
        $x_2_3 = "ruamylove.28@gmail.com" wide //weight: 2
        $x_2_4 = ".frog" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

