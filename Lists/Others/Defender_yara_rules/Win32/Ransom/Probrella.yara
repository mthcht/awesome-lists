rule Ransom_Win32_Probrella_A_2147717090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Probrella.A"
        threat_id = "2147717090"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Probrella"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 6d 74 70 2e 6e 6f 70 72 6f 62 6c 65 6d 62 72 6f 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 6f 63 6b 65 64 20 2d 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 43 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 61 73 73 77 6f 72 64 3a 00}  //weight: 1, accuracy: High
        $x_1_5 = "decryptor2013@gmail.com," ascii //weight: 1
        $x_1_6 = {2d 2d 2d 54 65 63 68 2d 42 65 67 69 6e 2d 2d 2d 00}  //weight: 1, accuracy: High
        $x_1_7 = {55 6d 62 72 65 6c 6c 61 20 43 6f 72 70 6f 72 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = {4f 75 72 20 57 6f 72 6b 20 49 73 20 59 6f 75 72 20 4c 69 66 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {2e 6c 6f 63 6b 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_Win32_Probrella_A_2147717101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Probrella.A!!Probrella.gen!A"
        threat_id = "2147717101"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Probrella"
        severity = "Critical"
        info = "Probrella: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 6d 74 70 2e 6e 6f 70 72 6f 62 6c 65 6d 62 72 6f 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 6f 63 6b 65 64 20 2d 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 43 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 61 73 73 77 6f 72 64 3a 00}  //weight: 1, accuracy: High
        $x_1_5 = "decryptor2013@gmail.com," ascii //weight: 1
        $x_1_6 = {2d 2d 2d 54 65 63 68 2d 42 65 67 69 6e 2d 2d 2d 00}  //weight: 1, accuracy: High
        $x_1_7 = {55 6d 62 72 65 6c 6c 61 20 43 6f 72 70 6f 72 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = {4f 75 72 20 57 6f 72 6b 20 49 73 20 59 6f 75 72 20 4c 69 66 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {2e 6c 6f 63 6b 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

