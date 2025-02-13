rule Ransom_Win32_Satancrypt_A_2147726650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Satancrypt.A"
        threat_id = "2147726650"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Satancrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Some files have been encrypted" wide //weight: 2
        $x_2_2 = "Please send 0.5 bit coins to my wallet address" wide //weight: 2
        $x_2_3 = "If you paid, send the machine code to my email" wide //weight: 2
        $x_2_4 = "Satan Cryptor V2.1" wide //weight: 2
        $x_2_5 = "satan_pro@mail.ru" wide //weight: 2
        $x_2_6 = "1BEDcx8n4PdydUNC4gcwLSbUCVksJSMuo8" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

