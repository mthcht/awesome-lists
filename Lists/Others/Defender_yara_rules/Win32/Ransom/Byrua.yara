rule Ransom_Win32_Byrua_A_2147721232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Byrua.A!rsm"
        threat_id = "2147721232"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Byrua"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 00 4c 00 45 00 5a 00 41 00 5d 00 ?? ?? 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-30] 3a 00 31 00 33 00 33 00 37 00 2f 00 64 00 65 00 70 00 6f 00 73 00 69 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 00 53 79 73 74 65 6d 2e 4e 65 74 2e 53 65 63 75 72 69 74 79 00 00 [0-15] 2e 00 72 00 75 00 62 00 79 00 00 09 2e 00 74 00 78 00 74 00 00 09 2e 00 64 00 6f 00 63 00 00 0b 2e 00 64 00 6f 00 63 00 78 00 00 09 2e 00 78 00 6c 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

