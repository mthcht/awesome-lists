rule Ransom_Win32_Lecrypt_A_2147709114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lecrypt.A"
        threat_id = "2147709114"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LeChiffre" ascii //weight: 2
        $x_1_2 = "php?shutdown=&reason=" ascii //weight: 1
        $x_1_3 = "insert=&servername=" ascii //weight: 1
        $x_1_4 = "*.*crypt" ascii //weight: 1
        $x_1_5 = "?changecomment=&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

