rule Ransom_Win32_Milicry_A_2147717247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Milicry.A"
        threat_id = "2147717247"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Milicry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 59 5f 51 57 65 6d 73 61 64 6b 6a 61 73 64 00 00 21 00 52 00 65 00 63 00 6f 00 76 00 65 00 72}  //weight: 2, accuracy: High
        $x_2_2 = {73 79 73 00 65 6c 65 76 00 00 00 00 25 73 2e 63 72 79 00 00 25 73 5c 25 75 2e 74 6d 70 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {25 73 5c 2a 2e 2a 00 00 25 73 5c 6f 6c 64 5f 73 68 6f 72 74 63 75 74 73 00 00 00 00 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 65 2e 6f 72 67 2f 25}  //weight: 1, accuracy: High
        $x_1_4 = {69 6d 67 75 72 2e 63 6f 6d 00 00 00 2f 75 70 6c 6f 61 64 2f 63 68 65 63 6b 63 61 70 74 63 68 61 00 00 00 00 74 6f 74 61 6c 5f 75 70 6c 6f 61 64 73 3d 31 26 63 72 65 61 74 65 5f 61 6c 62 75 6d}  //weight: 1, accuracy: High
        $x_1_5 = {26 77 69 66 69 3d 6d 61 63 3a 25 73 7c 73 73 69 64 3a 25 73 7c 73 73 3a 25 64 00 00 2f 6d 61 70 73 2f 61 70 69 2f 62 72 6f 77 73 65 72 6c 6f 63 61 74 69 6f 6e 2f 6a 73 6f 6e 3f 62 72 6f 77 73}  //weight: 1, accuracy: High
        $x_2_6 = {69 76 00 00 6b 65 79 00 72 65 63 00 6c 65 6e 00 72 00 75 00 6e 00 61 00 73 00 00 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 00 00 00 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00}  //weight: 2, accuracy: High
        $x_1_7 = {66 00 64 69 70 00 78 33 66 00 6d 65 66 00 72 61 77 00 6c 6f 67 00 6f 64 67 00 75 6f 70 00 70 6f 74 78 00 70 6f 74 6d 00 70 70 74 78 00 72 73 73 00 70 70 74 6d 00 61 61 66 00 78 6c 61 00 73 78}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 5c 21 52 65 63 6f 76 65 72 79 5f 25 73 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = "uses military grade elliptic curve cryptography and you" ascii //weight: 1
        $x_1_10 = {41 74 74 65 6e 74 69 6f 6e 21 20 41 74 74 65 6e 74 69 6f 6e 21 20 54 68 69 73 20 69 73 20 6e 6f 74 20 61 20 74 65 73 74 21 00 00 00 41 6c 6c 20 79 6f 75 20 64 6f 63 75 6d 65 6e 74 73 2c 20 64 61 74 61 20 62 61 73 65 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73}  //weight: 1, accuracy: High
        $x_1_11 = "sage.notice\\shell\\open\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Milicry_A_2147717265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Milicry.A!!Milicry.A"
        threat_id = "2147717265"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Milicry"
        severity = "Critical"
        info = "Milicry: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 59 5f 51 57 65 6d 73 61 64 6b 6a 61 73 64 00 00 21 00 52 00 65 00 63 00 6f 00 76 00 65 00 72}  //weight: 2, accuracy: High
        $x_2_2 = {73 79 73 00 65 6c 65 76 00 00 00 00 25 73 2e 63 72 79 00 00 25 73 5c 25 75 2e 74 6d 70 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {25 73 5c 2a 2e 2a 00 00 25 73 5c 6f 6c 64 5f 73 68 6f 72 74 63 75 74 73 00 00 00 00 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 65 2e 6f 72 67 2f 25}  //weight: 1, accuracy: High
        $x_1_4 = {69 6d 67 75 72 2e 63 6f 6d 00 00 00 2f 75 70 6c 6f 61 64 2f 63 68 65 63 6b 63 61 70 74 63 68 61 00 00 00 00 74 6f 74 61 6c 5f 75 70 6c 6f 61 64 73 3d 31 26 63 72 65 61 74 65 5f 61 6c 62 75 6d}  //weight: 1, accuracy: High
        $x_1_5 = {26 77 69 66 69 3d 6d 61 63 3a 25 73 7c 73 73 69 64 3a 25 73 7c 73 73 3a 25 64 00 00 2f 6d 61 70 73 2f 61 70 69 2f 62 72 6f 77 73 65 72 6c 6f 63 61 74 69 6f 6e 2f 6a 73 6f 6e 3f 62 72 6f 77 73}  //weight: 1, accuracy: High
        $x_2_6 = {69 76 00 00 6b 65 79 00 72 65 63 00 6c 65 6e 00 72 00 75 00 6e 00 61 00 73 00 00 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 00 00 00 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00}  //weight: 2, accuracy: High
        $x_1_7 = {66 00 64 69 70 00 78 33 66 00 6d 65 66 00 72 61 77 00 6c 6f 67 00 6f 64 67 00 75 6f 70 00 70 6f 74 78 00 70 6f 74 6d 00 70 70 74 78 00 72 73 73 00 70 70 74 6d 00 61 61 66 00 78 6c 61 00 73 78}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 5c 21 52 65 63 6f 76 65 72 79 5f 25 73 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = "uses military grade elliptic curve cryptography and you" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Milicry_B_2147719569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Milicry.B"
        threat_id = "2147719569"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Milicry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 25 73 2e 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 77 69 66 69 3d 6d 61 63 3a 25 73 7c 73 73 69 64 3a 25 73 7c 73 73 3a 25 64 00 00 2f 6d 61 70 73 2f 61 70 69 2f 62 72 6f 77 73 65 72 6c 6f 63 61 74 69 6f 6e 2f 6a 73 6f 6e 3f 62 72 6f 77 73}  //weight: 1, accuracy: High
        $x_1_3 = "!Recovery_%s.html" ascii //weight: 1
        $x_1_4 = "images and videos and so on were encrypted by software known as SAGE" ascii //weight: 1
        $x_1_5 = {00 64 61 74 00 6d 78 30 00 63 64 00 70 64 62 00 78 71 78 00 6f 6c 64 00 63 6e 74 00 72 74 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Milicry_C_2147721191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Milicry.C!bit"
        threat_id = "2147721191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Milicry"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\!HELP_SOS.hta" ascii //weight: 1
        $x_1_2 = "delete shadows /all /quiet vssadmin.exe" wide //weight: 1
        $x_1_3 = "thumbs.db|desktop.ini|ntuser.dat|" wide //weight: 1
        $x_10_4 = "sage.notice" wide //weight: 10
        $x_10_5 = "encrypted by SAGE" wide //weight: 10
        $x_10_6 = "mbfce24rgn65bx3g" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Milicry_F_2147721821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Milicry.F!bit"
        threat_id = "2147721821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Milicry"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--killstart" ascii //weight: 1
        $x_1_2 = "--killmetro" ascii //weight: 1
        $x_1_3 = "--sbopenav" ascii //weight: 1
        $x_1_4 = "--resexplr" ascii //weight: 1
        $x_1_5 = "cmd.exe /c explorer.exe" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

