rule Ransom_Win64_GandCrab_PGAX_2147966870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GandCrab.PGAX!MTB"
        threat_id = "2147966870"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 00 54 00 6f 00 20 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 73 00 65 00 6e 00 64 00 20 00 [0-16] 20 00 42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 73 00 20 00 74 00 6f 00 20 00 [0-128] 20 00 77 00 69 00 74 00 68 00 69 00 6e 00 20 00 32 00 34 00 20 00 68 00 6f 00 75 00 72 00 73 00 20 00 [0-16] 20 00 61 00 66 00 74 00 65 00 72 00 20 00 32 00 34 00 20 00 68 00 6f 00 75 00 72 00 73 00}  //weight: 2, accuracy: Low
        $x_2_2 = {2e 54 6f 20 75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 20 73 65 6e 64 20 [0-16] 20 42 69 74 63 6f 69 6e 73 20 74 6f 20 [0-128] 20 77 69 74 68 69 6e 20 32 34 20 68 6f 75 72 73 20 [0-16] 20 61 66 74 65 72 20 32 34 20 68 6f 75 72 73}  //weight: 2, accuracy: Low
        $x_2_3 = {67 00 61 00 6e 00 64 00 63 00 72 00 61 00 62 00 2f 00 76 00 69 00 63 00 74 00 69 00 6d 00 2d 00 69 00 64 00 2f 00 [0-16] 2e 00 70 00 65 00 6d 00}  //weight: 2, accuracy: Low
        $x_2_4 = {67 61 6e 64 63 72 61 62 2f 76 69 63 74 69 6d 2d 69 64 2f [0-16] 2e 70 65 6d}  //weight: 2, accuracy: Low
        $x_2_5 = ".RANSOM" ascii //weight: 2
        $x_2_6 = "\\WindowsUpdate.locked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

