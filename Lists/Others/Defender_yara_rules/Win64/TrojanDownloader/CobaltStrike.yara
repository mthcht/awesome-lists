rule TrojanDownloader_Win64_CobaltStrike_PE_2147828690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CobaltStrike.PE!MTB"
        threat_id = "2147828690"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c9 48 03 c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 48 63 c9 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 c1 48 63 0d ?? ?? ?? ?? 48 2b c1 48 63 0d ?? ?? ?? ?? 48 03 4c 24 ?? 0f b6 04 01 8b 4c 24 04 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_CobaltStrike_A_2147893470_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CobaltStrike.A!MTB"
        threat_id = "2147893470"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 4c 42 02 66 3b 4c 47 02 75 ?? 48 83 c0 02 48 83 f8 0d 74 ?? 0f b7 0c 42 66 3b 0c 47 74 ?? 48 8d 55 10 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_CobaltStrike_B_2147893503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CobaltStrike.B!MTB"
        threat_id = "2147893503"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f9 8b c2 48 98 0f be 44 04 ?? 8b 4c 24 54 33 c8 8b c1}  //weight: 2, accuracy: Low
        $x_2_2 = {41 f7 e9 41 8b c9 41 ff c1 8b c2 c1 e8 ?? 03 d0 8d 04 52 2b c8 48 63 c1 0f b6 4c 04 ?? 41 30 4a ?? 49 63 c1 48 3b c3}  //weight: 2, accuracy: Low
        $x_2_3 = {48 63 c8 0f b6 44 0c ?? 41 30 00 ff c2 49 ff c0 48 63 c2 48 3b c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win64_CobaltStrike_CCGB_2147900132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CobaltStrike.CCGB!MTB"
        threat_id = "2147900132"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 85 68 bd 0d 00 48 8b 8d 68 bd 0d 00 48 8d 15 14 2f 00 00 45 31 c0 45 31 c9 c7 44 24 20 00 00 00 80 48 c7 44 24 28 00 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_CobaltStrike_GLG_2147911091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CobaltStrike.GLG!MTB"
        threat_id = "2147911091"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rev.aes" wide //weight: 1
        $x_1_2 = "38.207.176.86" wide //weight: 1
        $x_1_3 = "lease\\Project5.pdb" ascii //weight: 1
        $x_1_4 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_CobaltStrike_RJD_2147931071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CobaltStrike.RJD!MTB"
        threat_id = "2147931071"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 08 8b 45 18 41 89 c0 48 8b 55 e8 48 8b 45 f8 48 01 d0 44 31 c1 89 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

