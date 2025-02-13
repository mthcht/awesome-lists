rule TrojanDropper_Win32_Lofaul_A_2147697790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lofaul.A"
        threat_id = "2147697790"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lofaul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 6f 20 74 6f 20 73 61 66 65 20 6d 6f 64 65 20 61 6e 64 06 1e 72 65 6d 6f 76 65 20 61 6c 6c 20 66 69 6c 65 73 20 69 6e 20 79 6f 75 72 20 73 74 61 72 74 06 14 6d 65 6e 75 20 73 74 61 72 74 75 70 20 66 6f 6c 64 65 72 2e}  //weight: 1, accuracy: High
        $x_1_2 = {5c 6d 69 6e 61 72 6b 6f 2e 65 78 65 [0-15] 6f 70 65 6e [0-15] 45 72 72 6f 72 20 39 30 30 34 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

