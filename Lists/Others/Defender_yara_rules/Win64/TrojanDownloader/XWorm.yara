rule TrojanDownloader_Win64_XWorm_SX_2147953288_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/XWorm.SX!MTB"
        threat_id = "2147953288"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 0f 6e c8 f3 0f e6 c9 f2 0f 58 c0 f2 0f 5c c8 f2 0f 59 ca f2 0f 11 4c 24 30 45 8d 14 5e 44 03 d3}  //weight: 3, accuracy: High
        $x_2_2 = {4c 8d 45 cf 44 89 74 24 28 48 8d 15 ?? ?? ?? ?? 4c 0f 47 45 cf 45 33 c9 33 c9 48 89 74 24 20 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_XWorm_PSW_2147953410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/XWorm.PSW!MTB"
        threat_id = "2147953410"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hidden -NoProfile -ExecutionPolicy Bypass -Command \"iex (iwr" ascii //weight: 1
        $x_1_2 = "https://github.com/robertoaguilarfields-blip/my-proyecto/raw/refs/heads/main/bypass.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

