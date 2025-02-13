rule Ransom_Win32_Uiwix_A_2147721484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Uiwix.A!rsm"
        threat_id = "2147721484"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Uiwix"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "statistic||" ascii //weight: 1
        $x_1_2 = "%%ID%%.UIWIX" ascii //weight: 1
        $x_1_3 = {2e 6f 6e 69 6f 6e 2f [0-16] 2e 70 68 70 3b}  //weight: 1, accuracy: Low
        $x_1_4 = "_DECODE_FILES.txt" ascii //weight: 1
        $x_1_5 = ":TMemModule.:" ascii //weight: 1
        $x_1_6 = {2d 31 00 30 00 65 78 70 6c 6f 69 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 66 64 58 72 58 7a 51 42 63 4b 4c 6c 73 72 5a 00}  //weight: 1, accuracy: High
        $x_1_8 = {0f b6 1a 3a 5d ff 75 08 0f b6 01 88 45 fe eb 07 40 41 42 3c 3e 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Uiwix_A_2147721487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Uiwix.A!!Uiwix.gen!A"
        threat_id = "2147721487"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Uiwix"
        severity = "Critical"
        info = "Uiwix: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "statistic||" ascii //weight: 1
        $x_1_2 = ":TMemModule.:" ascii //weight: 1
        $x_1_3 = {2e 6f 6e 69 6f 6e 2f [0-16] 2e 70 68 70 3b}  //weight: 1, accuracy: Low
        $x_1_4 = "%%ID%%.UIWIX" ascii //weight: 1
        $x_1_5 = "_DECODE_FILES.txt" ascii //weight: 1
        $x_1_6 = {2d 31 00 30 00 65 78 70 6c 6f 69 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 66 64 58 72 58 7a 51 42 63 4b 4c 6c 73 72 5a 00}  //weight: 1, accuracy: High
        $x_1_8 = {0f b6 1a 3a 5d ff 75 08 0f b6 01 88 45 fe eb 07 40 41 42 3c 3e 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

