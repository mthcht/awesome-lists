rule TrojanDropper_Win32_Tiebho_A_2147618601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tiebho.A"
        threat_id = "2147618601"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiebho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {67 72 65 61 74 64 65 61 [0-3] 73 63 74 68 2e 63 6f 6d}  //weight: 2, accuracy: Low
        $x_2_2 = "D032570A-5F63-4812-A094-87D007C23012" ascii //weight: 2
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Control\\BHOinit" ascii //weight: 1
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 00 45 6e 61 62 6c 65 48 74 74 70 31 5f 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

