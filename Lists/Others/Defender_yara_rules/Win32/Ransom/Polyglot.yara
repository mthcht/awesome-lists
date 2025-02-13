rule Ransom_Win32_Polyglot_A_2147717609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Polyglot.A"
        threat_id = "2147717609"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyglot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 75 6e 63 74 69 6f 6e 20 70 72 65 73 73 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 28 29 0d 0a 7b 0d 0a 09 76 69 73 69 62 6c 65 45 6c 65 6d 65 6e 74 73 28 22 62 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 22 29 3b}  //weight: 1, accuracy: High
        $x_1_2 = "function setCryptedFile(strFiles)" ascii //weight: 1
        $x_2_3 = {66 39 4d fa 76 25 66 0f b6 55 f8 8b 45 fc 8b 75 0c 53 8a 18 32 da 32 d9 66 81 e3 ff 00 41 66 89 1e 40 46 46 66 3b 4d fa 72 e8 5b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Polyglot_A_2147717610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Polyglot.A!!Polyglot.gen!A"
        threat_id = "2147717610"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyglot"
        severity = "Critical"
        info = "Polyglot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setCryptedFile" ascii //weight: 1
        $x_1_2 = "#decrypt_demo_files" ascii //weight: 1
        $x_1_3 = "ReadMeFilesDecrypt.txt!!!" ascii //weight: 1
        $x_2_4 = {66 75 6e 63 74 69 6f 6e 20 70 72 65 73 73 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 28 29 0d 0a 7b 0d 0a 09 76 69 73 69 62 6c 65 45 6c 65 6d 65 6e 74 73 28 22 62 5f 64 65 6d 6f 5f 64 65 63 72 79 70 74 22 29 3b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

