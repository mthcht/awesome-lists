rule Backdoor_Win32_RainbowRoad_A_2147835394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RainbowRoad.A"
        threat_id = "2147835394"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RainbowRoad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 69 72 65 63 74 6f 72 79 20 44 65 6c 65 74 65 64 00 5c 64 65 6c 2e 76 62 73 00 73 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_2 = {69 66 20 28 66 31 2e 46 69 6c 65 45 78 69 73 74 73 28 22 00 22 29 29 20 74 68 65 6e 20 66 31 2e 44 65 6c 65 74 65 46 69 6c 65 28 22 00 22 29 0a 69 66 20 28 66 32 2e 46 69 6c 65 45 78 69 73 74 73 28 22 00 22 29 29 20 74 68 65 6e 20 66 32 2e 44 65 6c 65 74 65 46 69 6c 65 28 22 00 22 29 0a 69 66 20 28 66 33 2e 46 69 6c 65 45 78 69 73 74 73 28 22 00 22 29 29 20 74 68 65 6e 20 66 33 2e 44 65 6c 65 74 65 46 69 6c 65 28 22 00 22 29 65 6e 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

