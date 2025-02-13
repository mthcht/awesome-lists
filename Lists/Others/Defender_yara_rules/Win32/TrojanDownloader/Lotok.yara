rule TrojanDownloader_Win32_Lotok_A_2147894271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lotok.A!MTB"
        threat_id = "2147894271"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 8d 8d 00 f0 ff ff 68 00 10 00 00 51 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff 7e ?? 8d 85 00 f0 ff ff 57 50 8b 46 04 8d 44 30 10 50 e8 ?? ?? ?? ?? 01 7e 04 83 c4 0c 39 5e 04}  //weight: 2, accuracy: Low
        $x_2_2 = {ff 75 08 ff 15 ?? ?? ?? ?? ff 75 0c 8b f8 66 c7 45 f0 02 00 ff 15 ?? ?? ?? ?? 66 89 45 f2 8b 47 0c 6a 10 8b 00 8b 00 89 45 f4 8d 45 f0 50 ff 76 08 ff 15 ?? ?? ?? ?? 83 f8 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Lotok_DH_2147900593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lotok.DH!MTB"
        threat_id = "2147900593"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 06 60 fd 89 c8 52 5b fc 61 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Lotok_DG_2147900618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lotok.DG!MTB"
        threat_id = "2147900618"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 51 66 59 32 06 66 56 66 5e 88 07 9c 66 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

