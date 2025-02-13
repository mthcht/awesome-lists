rule TrojanDownloader_Win64_Lazy_RDA_2147835630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Lazy.RDA!MTB"
        threat_id = "2147835630"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 33 01 00 00 66 03 c2 66 33 c1}  //weight: 2, accuracy: High
        $x_2_2 = {48 63 c2 48 8d 4d ?? 48 03 c8 8d 42 ?? 30 01 ff c2 83 fa}  //weight: 2, accuracy: Low
        $x_1_3 = "wasd-" ascii //weight: 1
        $x_1_4 = "//cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_5 = "chrome.exe" ascii //weight: 1
        $x_1_6 = "Fortnite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Lazy_E_2147926183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Lazy.E!MTB"
        threat_id = "2147926183"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d9 eb d9 fc 0f 31 48 c1 e2 20 48 0b c2 48 2b c1 49 3b c1}  //weight: 1, accuracy: High
        $x_1_2 = {49 ff ca 4d 33 db 48 ff c8 48 83 c4 08 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {3b c8 48 f7 d3 0f 42 c8 49 23 dc 49 8d 44 3d 00 8b f1 48 2b de 48 3b d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

