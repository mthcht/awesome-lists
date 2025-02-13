rule Virus_Win32_Azero_A_2147616829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Azero.gen!A"
        threat_id = "2147616829"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Azero"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 56 00 [0-8] 2e 00 65 00 78 00 65 00 [0-16] 2e 00 70 00 69 00 66 00 [0-64] 2e 00 73 00 63 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 20 00 44 00 61 00 74 00 61 00 [0-10] 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 [0-10] 5c 00 4d 00 65 00 64 00 69 00 61 00 20 00 50 00 6c 00 61 00 79 00 65 00 72 00 [0-8] 5c 00 4f 00 66 00 66 00 69 00 63 00 65 00 [0-8] 5c 00 57 00 6f 00 72 00 64 00 [0-8] 5c 00 45 00 78 00 63 00 65 00 6c 00 [0-16] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

