rule VirTool_Win32_Drobedesz_A_2147902651_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Drobedesz.A!MTB"
        threat_id = "2147902651"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Drobedesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a fe 68 10 38 40 00 68 7f 16 40 00 64 a1 00 00 00 00 50 83 ec 14 a1 04 50 40 00 31 45 f8 33 c5 89 45 e4 53 56 57 50 ?? ?? ?? 64 a3 00 00 00 00 89 65 e8 6a 10 ?? ?? ?? ?? ?? ?? 3d f1}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc fe ff ff ff 68 c4 32 40 00 ?? ?? ?? ?? ?? ?? 8b f0 85 f6 ?? ?? 68 d0 32 40 00 56 8b 3d 50 30 40 00 ?? ?? 8b d8 85 db ?? ?? 68 e4 32 40 00 56 ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d8 89 9d 04 fd ff ff 85 db ?? ?? ?? ?? ?? ?? 83 3c bd 88 53 40 00 00 ?? ?? ?? ?? ?? ?? 6a 40 68 00 30 00 00 ff 34 bd 7c 53 40 00 6a 00 53 ?? ?? ?? ?? ?? ?? 89 45 f8 85 c0 ?? ?? ?? ?? ?? ?? 6a 00 ff 34 bd 7c 53 40 00 ff 34 bd 88 53 40 00 50 53 ?? ?? ?? ?? ?? ?? 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

