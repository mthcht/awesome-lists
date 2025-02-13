rule TrojanDropper_Win32_Stioldaat_STB_2147781464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Stioldaat.STB"
        threat_id = "2147781464"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Stioldaat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4c 69 62 31 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 [0-10] 44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 [0-6] 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "\\relea.pdb" ascii //weight: 1
        $x_2_4 = {81 f7 6e 74 65 6c 8b 45 e8 35 69 6e 65 49 89 45 f8 8b 45 e0 35 47 65 6e 75 89 45 fc 33 c0 40}  //weight: 2, accuracy: High
        $x_2_5 = {6a 00 68 00 ca 9a 3b 52 50 8b f1 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

