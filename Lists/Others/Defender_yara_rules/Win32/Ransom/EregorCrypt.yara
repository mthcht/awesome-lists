rule Ransom_Win32_EregorCrypt_G_2147765806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EregorCrypt.G!MSR"
        threat_id = "2147765806"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EregorCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "IFVCVbAErvTeBRgUN1vQHNp5FVtc1WVi" ascii //weight: 2
        $x_2_2 = "Lo0C03icERjo0J" ascii //weight: 2
        $x_2_3 = "h3kpJ0QEAC5OJC" ascii //weight: 2
        $x_2_4 = "6uLNEu5AJnCi2FEUB35EUm7AfMc" ascii //weight: 2
        $x_1_5 = "KojihuDJUFDHGufhdjnbgDfgudfhdfg3" ascii //weight: 1
        $x_2_6 = "ptLfuESbgJkAmR5cW2uJVv" ascii //weight: 2
        $x_2_7 = "rBiQVtMjL6a0q7bSJ34LtGmu" ascii //weight: 2
        $x_2_8 = "h13cEeM52mg" ascii //weight: 2
        $x_2_9 = "EBUa7egBVJ1sfnppVhnAcFQTb5Kov3TCF60HAVntw" ascii //weight: 2
        $x_1_10 = "iD8s8SJDhHFJDkdkfOFig8g8hDjSkDlA" ascii //weight: 1
        $x_2_11 = "expand 32-byte kexpand 16-byte k" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            (all of ($x*))
        )
}

