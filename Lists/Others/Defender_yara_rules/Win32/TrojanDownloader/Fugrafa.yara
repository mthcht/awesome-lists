rule TrojanDownloader_Win32_Fugrafa_A_2147754710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fugrafa.A!MTB"
        threat_id = "2147754710"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 83 7a 14 10 8b c2 53 56 57 8b f1 72 02 8b 02 83 7e 14 10 72 02 8b 0e 8b 5a 10 8d 56 10 8b 3a 53 50 89 55 fc 8b d7 51 ?? ?? ?? ?? ?? 8b d0 83 c4 0c 83 fa ff 74 30 3b fa 72 33 8b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Fugrafa_B_2147935079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fugrafa.B!MTB"
        threat_id = "2147935079"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 38 6a 00 8d 45 f8 c7 45 f8 00 00 00 00 50 ff 76 34 ff 76 28 57}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 83 7a 14 10 8b c2 56 8b f1 89 75 fc 72 02 8b 02 ff 72 10 50 51 8b 4d 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

