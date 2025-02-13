rule Ransom_MSIL_Springbeep_A_2147725389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Springbeep.A!bit"
        threat_id = "2147725389"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Springbeep"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\winload.bin" wide //weight: 1
        $x_1_2 = "\\cmdtool.exe" wide //weight: 1
        $x_1_3 = "\\Springbeep.lock" wide //weight: 1
        $x_1_4 = "/Autorun" wide //weight: 1
        $x_1_5 = "\\Release\\Springbeep.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

