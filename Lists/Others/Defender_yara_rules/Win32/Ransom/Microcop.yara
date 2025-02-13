rule Ransom_Win32_Microcop_2147750352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Microcop!MSR"
        threat_id = "2147750352"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Microcop"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-16] 2e 00 6a 00 70 00 67 00 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-32] 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 [0-16] 2e 00 6a 00 70 00 67 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 00 46 00 20 00 4e 00 4f 00 54 00 20 00 46 00 49 00 4c 00 45 00 45 00 58 00 49 00 53 00 54 00 53 00 20 00 28 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-32] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 53 00 65 00 72 00 76 00 2e 00 61 00 75 00 33 00 2e 00 74 00 62 00 6c 00 22 00 20 00 2c 00 20 00 [0-32] 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = "FILECREATESHORTCUT ( EXECUTE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

