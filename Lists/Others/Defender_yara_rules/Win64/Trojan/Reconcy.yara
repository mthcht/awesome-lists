rule Trojan_Win64_Reconcy_A_2147956507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reconcy.A!AMTB"
        threat_id = "2147956507"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reconcy"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 6f 75 74 66 69 6c 65 20 27 63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 [0-16] 2e 65 78 65 27 3b 20 53 74 61 72 74 2d 53 6c 65 65 70 20 34}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 [0-1] 3a 2f 2f 66 69 6c 65 73 2e 6d 61 6e 75 73 63 64 6e 2e 63 6f 6d 2f 75 73 65 72 5f 75 70 6c 6f 61 64 5f 62 79 5f 6d 6f 64 75 6c 65 2f 73 65 73 73 69 6f 6e 5f 66 69 6c 65 [0-64] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 [0-5] 53 74 61 72 74 2d 53 6c 65 65 70}  //weight: 1, accuracy: Low
        $x_1_4 = "powershell -Command \"Add-MpPreference -ExclusionPath 'C:\\*','D:\\*','E:\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

