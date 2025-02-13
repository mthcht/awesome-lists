rule Ransom_Win32_Yoyorypt_A_2147721955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Yoyorypt.A"
        threat_id = "2147721955"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoyorypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /C ping 1.1.1.1 -n 5 -w 3000 > Nul & Del \"%s\"" ascii //weight: 1
        $x_1_2 = "read_to_txt_file.yyto" ascii //weight: 1
        $x_1_3 = "help_to_decrypt.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

