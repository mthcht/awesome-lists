rule Ransom_Win32_Vanhelsing_DA_2147936357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vanhelsing.DA!MTB"
        threat_id = "2147936357"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vanhelsing"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = ".vanhelsing" ascii //weight: 50
        $x_50_2 = {76 00 61 00 6e 00 68 00 65 00 6c 00 [0-100] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00}  //weight: 50, accuracy: Low
        $x_50_3 = {76 61 6e 68 65 6c [0-100] 2e 6f 6e 69 6f 6e}  //weight: 50, accuracy: Low
        $x_1_4 = {73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-30] 64 00 65 00 6c 00 65 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 68 61 64 6f 77 63 6f 70 79 [0-30] 64 65 6c 65 74 65}  //weight: 1, accuracy: Low
        $x_1_6 = "Download tor browser" ascii //weight: 1
        $x_1_7 = "lose all your date" ascii //weight: 1
        $x_1_8 = "pay the ransom" ascii //weight: 1
        $x_1_9 = "restore your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

