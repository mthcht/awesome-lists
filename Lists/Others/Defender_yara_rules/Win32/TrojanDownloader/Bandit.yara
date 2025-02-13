rule TrojanDownloader_Win32_Bandit_MR_2147742745_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bandit.MR!MTB"
        threat_id = "2147742745"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 81 fb ?? ?? ?? ?? 75 ?? 57 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 57 8d 85 ?? ?? ?? ?? 50 57 ff 15 ?? ?? ?? ?? 46 3b f3 7c 23 00 81 fb ?? ?? ?? ?? 75 ?? 8d 85 ?? ?? ?? ?? 50 57 57 57 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bandit_MS_2147743671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bandit.MS!MTB"
        threat_id = "2147743671"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d3 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c1 ea ?? 03 cb 03 55 ?? 33 d1 33 d6 2b fa 89 7d ?? 3d ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
        $x_1_2 = {c7 45 f8 20 37 ef c6}  //weight: 1, accuracy: High
        $x_1_3 = {81 c1 47 86 c8 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

