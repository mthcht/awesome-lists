rule Ransom_Win64_Pydomer_A_2147778213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Pydomer.A"
        threat_id = "2147778213"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Pydomer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 da b5 7a 4d 6c 23 49 96 5e 66 f2 57 94 4a a5 aa ae 96 aa aa ff d4 3d dd 35 ad 9e ee 2a 8a 92 6a 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Pydomer_B_2147778289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Pydomer.B"
        threat_id = "2147778289"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Pydomer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 da b5 5a 4d 6c 1b 49 76 ee 6e fe 8a 92 65 d9 e3 91 6c 8f 67 46 33 3b e3 1d cd ce c8 14 25 79 2d af c7 bb 22 25 52 d4 0f 25 91 12 29 36 3c cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

