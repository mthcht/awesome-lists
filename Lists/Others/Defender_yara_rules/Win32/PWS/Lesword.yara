rule PWS_Win32_Lesword_A_2147657653_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lesword.A"
        threat_id = "2147657653"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lesword"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\elsword.exe" ascii //weight: 1
        $x_1_2 = "\\data\\mailsmtp.dll" ascii //weight: 1
        $x_1_3 = "GameDll.dll" ascii //weight: 1
        $x_1_4 = "&ppwd=%s&mac=%s&mbh" ascii //weight: 1
        $x_1_5 = {74 14 8d 54 24 ?? 68 ?? ?? ?? 10 52 ff 15 ?? ?? ?? 10 85 c0 75 19 8b 44 24 ?? 50 6a 00 6a 01 ff d3 8b f0 6a 00 56 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lesword_B_2147657807_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lesword.B"
        threat_id = "2147657807"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lesword"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 64 26 6c 3d 25 73 26 73 6c 3d 25 73 26 6d 61 63 3d 25 73 26 6d 62 68 3d 25 64 [0-1] 4e 55 4c 4c [0-16] 7a 68 65 6e 67 74 75 32 2e 64 61 74 [0-32] 5c 64 6f 77 6e 6c 6f 61 64 [0-2] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 55 49 43 61 63 68 65 00 63 6d 64 20 2f 63 20 25 73 [0-5] 61 2e 72 65 67 [0-5] 57 69 6e 64 6f 77 73 20 52 65 67}  //weight: 1, accuracy: Low
        $x_1_3 = {50 4f 53 54 [0-5] 2e 6a 70 67 [0-16] 41 43 44 [0-16] 25 73 3f 64 31 30 3d 25 73 26 64 38 30 3d 25 64 [0-10] 25 73 5c 25 73 2e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

