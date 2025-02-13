rule Ransom_Win32_Sorikrypt_A_2147712433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sorikrypt.A"
        threat_id = "2147712433"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sorikrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "0p3nSOurc3 X0r157, motherfucker!" ascii //weight: 1
        $x_1_2 = "Attention! All your files were encrypted!" ascii //weight: 1
        $x_1_3 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d ?? ?? 40 00 80 e9 41 c7 05 ?? ?? 40 00 3a 5c 2a 2e}  //weight: 1, accuracy: Low
        $x_2_4 = {83 fa 10 75 02 33 d2 ac 32 04 1a aa 42 49 75 f0 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

