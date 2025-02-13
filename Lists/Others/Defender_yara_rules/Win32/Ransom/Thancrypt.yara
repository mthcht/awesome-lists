rule Ransom_Win32_Thancrypt_A_2147726177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Thancrypt.A"
        threat_id = "2147726177"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Thancrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "D:\\Work\\Thanatos\\Release\\Thanatos.pdb" ascii //weight: 3
        $x_3_2 = "D:\\Thanatos\\Release\\Thanatos.pdb" ascii //weight: 3
        $x_3_3 = "\\Thanatos-master\\Debug\\Thanatos.pdb" ascii //weight: 3
        $x_2_4 = ".THANATOS" ascii //weight: 2
        $x_2_5 = ".PENTAGON" ascii //weight: 2
        $x_2_6 = "\\Desktop\\README.txt" ascii //weight: 2
        $x_2_7 = {41 6c 6c 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 20 69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 30 2e 30 31 20 42 54 43 20 74 6f 20 74 68 65 20 73 70 65 63 69 66 69 65 64 20 42 54 43 20 77 61 6c 6c 65 74 0a 0a 31 44 52 41 73 78 57 34 63 4b 41 44 31 42 43 53 39 6d 32 64 75 74 64 75 48 69 33 46 4b 71 51 6e 5a 46}  //weight: 2, accuracy: High
        $x_1_8 = "Mozilla/5.0 (Windows NT 6.1) Thanatos/1.1" wide //weight: 1
        $x_1_9 = "taskkill /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

