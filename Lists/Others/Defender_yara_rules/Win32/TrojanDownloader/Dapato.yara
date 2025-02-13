rule TrojanDownloader_Win32_Dapato_H_2147659958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dapato.H"
        threat_id = "2147659958"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set WriteStuff = FSY.OpenTextFile(ALYY & VRFY, 8, True)" wide //weight: 1
        $x_1_2 = "\\msddn.vbs" wide //weight: 1
        $x_1_3 = {8b 08 ff 51 7c 8d 55 b0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 b0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 b0}  //weight: 1, accuracy: Low
        $x_1_4 = "For i = 1 To LenB( OBH.ResponseBody )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dapato_L_2147682662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dapato.L"
        threat_id = "2147682662"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 5c 76 78 73 33 32 2e 65 78 65 00 00 68 74 74 70 73 3a 2f 2f [0-15] 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-15] 2f 76 78 73 33 32 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 5c 76 78 73 33 32 2e 65 78 65 00 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {3a 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 00 00 ff ff ff ff 09 00 00 00 45 6e 61 62 6c 65 4c 55 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

