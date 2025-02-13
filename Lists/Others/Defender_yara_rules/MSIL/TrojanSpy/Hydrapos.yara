rule TrojanSpy_MSIL_Hydrapos_A_2147727386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hydrapos.A!bit"
        threat_id = "2147727386"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hydrapos"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dump.php?w=Infectado&&arq=" wide //weight: 1
        $x_1_2 = "arq=atualiza.txt&&usr=" wide //weight: 1
        $x_1_3 = "uploads\\proctrue.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

