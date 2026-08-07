rule Backdoor_Win64_AusterePurlin_A_2147975420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AusterePurlin.A!dha"
        threat_id = "2147975420"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AusterePurlin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/agent/poll?token=" wide //weight: 1
        $x_1_2 = "Failed to upload file to server, status:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_AusterePurlin_AMS_2147975773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AusterePurlin.AMS!MTB"
        threat_id = "2147975773"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AusterePurlin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 15 b8 99 02 00 48 8d 0d c9 99 02 00 e8 ?? ?? ?? ?? 84 c0 0f 84 85 00 00 00 33 c0 c7 44 24 20 c0 d4 01 00 0f 57 c0 c7 44 24 24 88 13 00 00 0f 11 44 24 28 48 8d 4c 24 20 88 44 24 28 48 89 44 24 38 48 c7 44 24 40 0f 00 00 00 48 89 44 24 48}  //weight: 3, accuracy: Low
        $x_2_2 = "CheckForUpdates" ascii //weight: 2
        $x_1_3 = "pcName" ascii //weight: 1
        $x_1_4 = "userName" ascii //weight: 1
        $x_1_5 = "domainName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

