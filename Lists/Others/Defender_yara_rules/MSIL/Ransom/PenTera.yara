rule Ransom_MSIL_PenTera_F_2147830438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/PenTera.F!MSR"
        threat_id = "2147830438"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PenTera"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomNote.PNT-RNSM" ascii //weight: 1
        $x_1_2 = "PenterWare.exe" ascii //weight: 1
        $x_1_3 = "Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

