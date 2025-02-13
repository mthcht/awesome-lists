rule PWS_Win32_Yatkutur_B_2147658159_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yatkutur.B"
        threat_id = "2147658159"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yatkutur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "teclado virtual." wide //weight: 2
        $x_2_2 = "Cadastro" ascii //weight: 2
        $x_2_3 = "edtsenha" ascii //weight: 2
        $x_2_4 = "Brasil" wide //weight: 2
        $x_2_5 = "banking" ascii //weight: 2
        $x_2_6 = "santander" wide //weight: 2
        $x_1_7 = "AppHook" ascii //weight: 1
        $x_1_8 = "MouseHook" ascii //weight: 1
        $x_1_9 = "arquivo" ascii //weight: 1
        $x_1_10 = "privac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

