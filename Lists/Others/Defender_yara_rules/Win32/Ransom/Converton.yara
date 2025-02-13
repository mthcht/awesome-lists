rule Ransom_Win32_Converton_A_2147711712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Converton.A"
        threat_id = "2147711712"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Converton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&end_crypt_time=%d&count_files_crypted=%d" ascii //weight: 1
        $x_1_2 = "\\\\?\\%s%c%c%c%c%c%c" ascii //weight: 1
        $x_2_3 = {25 00 30 00 32 00 78 00 [0-8] 43 00 6f 00 76 00 65 00 72 00 74 00 6f 00 6e 00 [0-8] 25 00 78 00 25 00 78 00 25 00 78 00 25 00 78 00}  //weight: 2, accuracy: Low
        $x_2_4 = {25 30 32 78 [0-8] 43 6f 76 65 72 74 6f 6e [0-8] 25 78 25 78 25 78 25 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

