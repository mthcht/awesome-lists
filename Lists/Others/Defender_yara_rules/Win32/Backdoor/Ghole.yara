rule Backdoor_Win32_Ghole_2147693763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ghole!dha"
        threat_id = "2147693763"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghole"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 6e 69 67 68 74 6c 79 5c 73 61 6e 64 62 6f 78 5f 61 76 67 31 30 5f 76 63 39 5f 53 50 31 5f 32 30 31 31 [0-48] 5c 52 65 6c 65 61 73 65 5f 55 6e 69 63 6f 64 65 5f 76 73 39 30 5c 57 69 6e 33 32 5c 61 76 67 61 6d 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 5c 6d 6f 64 75 6c 65 73 5c 65 78 70 6c 6f 69 74 73 5c 6c 69 74 74 6c 65 74 6f 6f 6c 73 5c 61 67 65 6e 74 5f 77 72 61 70 70 65 72 5c [0-48] 5c 77 72 61 70 70 65 72 33 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

