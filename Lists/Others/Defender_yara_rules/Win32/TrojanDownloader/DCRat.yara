rule TrojanDownloader_Win32_DCRat_A_2147917300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DCRat.A!MTB"
        threat_id = "2147917300"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 8b c8 8b 45 ?? 8b 10 8b 42 ?? 66 0f b6 14 18 33 ca}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_DCRat_B_2147918306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DCRat.B!MTB"
        threat_id = "2147918306"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 c7 45 ?? ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 8b c7 c1 e8 ?? 25 ?? ?? ?? ?? f7 75 ?? 66 8b 84 ?? ?? ?? ?? ?? 66 89 ?? ?? 43 3b de}  //weight: 2, accuracy: Low
        $x_4_2 = {0f be ca c1 cb ?? 80 fa ?? 8d 41 ?? 0f 4c c1 03 d8 47 8a 17 84 d2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

