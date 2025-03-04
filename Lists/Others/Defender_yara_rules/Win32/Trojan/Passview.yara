rule Trojan_Win32_Passview_MB_2147813153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Passview.MB!MTB"
        threat_id = "2147813153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Passview"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 47 0c 8b 4d f4 8b 07 89 0c b0 8b 75 0c 8b 4d e4 8b 7d f8 8a 01 88 45 fc 8b d7 8d 45 d0 e8 ?? ?? ?? ?? 8b 45 d0 8a 4d fc 88 0c 38 47 89 7d f8 89 5d e8 ff 45 f4 8b 45 f4 38 1c 30 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "encryptedPassword" ascii //weight: 1
        $x_1_3 = "CryptDecrypt" ascii //weight: 1
        $x_1_4 = "/deleteregkey" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "UnmapViewOfFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Passview_MA_2147813451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Passview.MA!MTB"
        threat_id = "2147813451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Passview"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 41 b5 f8 3b a1 ?? ?? ?? ?? 3a 4f ad 33 99 ?? ?? ?? ?? 0c 00 aa 00 60 d3 93}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 4d 61 69 6e 00 0d 01 2e 00 c4 a7 ca de d5 f9 b0 d4 b8 f6 d0 d4 bb af b9 a4 be df 20 2d 20 57 61 72 4d 70 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

