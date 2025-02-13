rule Ransom_Win32_Diavol_SA_2147909480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Diavol.SA"
        threat_id = "2147909480"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Diavol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 6c 00 6f 00 63 00 6b 00 63 00 72 00 79 00 2e 00 64 00 69 00 76 00 69 00 64 00 65 00 64 00 5c 00 77 00 69 00 70 00 65 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 69 00 65 00 73 00 36 00 34 00 5c 00 72 00 65 00 6c 00 6e 00 6f 00 63 00 72 00 74 00 5c 00 [0-255] 2e 00 70 00 64 00 62 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

