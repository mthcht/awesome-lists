rule TrojanDownloader_Win32_Pikabot_HU_2147899733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pikabot.HU!MTB"
        threat_id = "2147899733"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a6 46 46 4e 81 95 ?? ?? ?? ?? ?? ?? ?? ?? 10 35 ?? ?? ?? ?? 98 b3 ?? 35 ?? ?? ?? ?? 92 ad 1c ?? 96 af 11 35 ?? ?? ?? ?? 81 94 f4 ?? ?? ?? ?? ?? ?? ?? ?? 46 84 98 ?? ?? ?? ?? 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pikabot_HV_2147899928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pikabot.HV!MTB"
        threat_id = "2147899928"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 43 b6 3c ?? 66 c1 a2 ?? ?? ?? ?? ?? c1 32 ?? f1 80 d0 ?? 34 ?? d2 d6 3d ?? ?? ?? ?? 63 d3 81 c5 ?? ?? ?? ?? 30 cb 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pikabot_VH_2147903673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pikabot.VH!MTB"
        threat_id = "2147903673"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 0f b6 54 15 ?? 33 ca b8 ?? ?? ?? ?? c1 e0 ?? 0f be 94 05 ?? ?? ?? ?? c1 e2 ?? b8 ?? ?? ?? ?? 6b c0 ?? 0f be 84 05 ?? ?? ?? ?? 0f af d0 6b d2 ?? 8b 45 ?? 2b c2 8b 55 ?? 88 0c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

