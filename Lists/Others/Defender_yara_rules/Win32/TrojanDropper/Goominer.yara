rule TrojanDropper_Win32_Goominer_A_2147696720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Goominer.A"
        threat_id = "2147696720"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Goominer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6f 6f 67 6c 65 54 6f 6f 6c 42 61 72 [0-5] 5c 49 6e 73 74 61 6c 6c 47 6f 6f 67 6c 65 54 6f 6f 6c 42 61 72 5c 49 6e 73 74 61 6c 6c 47 6f 6f 67 6c 65 54 6f 6f 6c 42 61 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 49 6e 73 74 61 6c 6c 47 6f 6f 67 6c 65 54 6f 6f 6c 42 61 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {42 73 65 74 75 70 00 42 73 65 74 75 70 2e 65 78 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 6e 73 74 61 6c 6c 47 6f 6f 67 6c 65 54 6f 6f 6c 42 61 72 2e 50 72 6f 70 65 72 74 69 65 73 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3c 4d 6f 64 75 6c 65 3e 00 42 61 62 65 6c 41 74 74 72 69 62 75 74 65 00 [0-7] 52 65 73 6f 75 72 63 65 73 00 49 6e 73 74 61 6c 6c 47 6f 6f 67 6c 65 54 6f 6f 6c 42 61 72 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

