rule Ransom_Win32_Spectrypt_A_2147721803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spectrypt.A"
        threat_id = "2147721803"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spectrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\HowToDecryptIMPORTANT!.txt" wide //weight: 1
        $x_1_2 = "shadowcopy delete" ascii //weight: 1
        $x_1_3 = "a0142503.xsph.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

