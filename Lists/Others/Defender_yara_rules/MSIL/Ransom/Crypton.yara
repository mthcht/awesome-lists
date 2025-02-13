rule Ransom_MSIL_Crypton_B_2147751699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypton.B!MSR"
        threat_id = "2147751699"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypton"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Cry.Key" wide //weight: 2
        $x_2_2 = {59 00 6f 00 75 00 72 00 20 00 70 00 72 00 69 00 76 00 61 00 63 00 79 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 6e 00 64 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 [0-32] 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64}  //weight: 2, accuracy: Low
        $x_2_3 = "\\README.TXT" wide //weight: 2
        $x_1_4 = {55 00 73 00 65 00 20 00 74 00 68 00 69 00 73 00 20 00 65 00 2d 00 6d 00 61 00 69 00 6c 00 20 00 74 00 6f 00 20 00 73 00 65 00 6e 00 64 00 20 00 61 00 20 00 [0-8] 20 00 67 00 75 00 69 00 74 00 61 00 72 00 20 00 74 00 6f}  //weight: 1, accuracy: Low
        $x_1_5 = "\\ReportGenerator\\obj\\Debug\\Crypton.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

