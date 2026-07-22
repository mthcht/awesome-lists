rule TrojanDownloader_Win32_Tedy_ARA_2147932416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tedy.ARA!MTB"
        threat_id = "2147932416"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b c8 0f b6 81 4d 2d 41 00 30 86 c5 58 41 00 83 c6 06 83 fe 12 0f 82 e9 fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tedy_G_2147974284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tedy.G!AMTB"
        threat_id = "2147974284"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 2d 72 65 73 6f 6c 76 65 20 [0-48] 2e [0-32] 3a 34 34 33 3a [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 68 74 74 70 [0-1] 3a 2f 2f 00 2e 01 2f [0-48] 2f [0-80] 2e 72 61 72}  //weight: 2, accuracy: Low
        $x_1_2 = "x -r -ep2 -hplimpid29033" ascii //weight: 1
        $x_1_3 = "AnyDesk.exe" ascii //weight: 1
        $x_1_4 = "curl.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

