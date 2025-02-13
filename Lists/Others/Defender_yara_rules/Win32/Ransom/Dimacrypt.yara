rule Ransom_Win32_Dimacrypt_A_2147723859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dimacrypt.A"
        threat_id = "2147723859"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dimacrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%ls\\DILMA_LOCKER_v1.hta" wide //weight: 2
        $x_2_2 = "d1lm4LocK7r_pR0V___" wide //weight: 2
        $x_1_3 = ".__dilmaV1" wide //weight: 1
        $x_1_4 = "DilmaLocke[R]" wide //weight: 1
        $x_1_5 = "n.Ransom.Win32.Dilma.Locker" wide //weight: 1
        $x_1_6 = "dilminha.dat" wide //weight: 1
        $x_1_7 = "RECUPERE_SEUS_ARQUIVOS.html" wide //weight: 1
        $x_1_8 = {00 00 5c 00 25 00 6c 00 73 00 5c 00 25 00 6c 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

