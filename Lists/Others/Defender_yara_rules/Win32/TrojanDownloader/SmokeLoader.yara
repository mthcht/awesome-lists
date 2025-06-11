rule TrojanDownloader_Win32_SmokeLoader_ARA_2147834299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SmokeLoader.ARA!MTB"
        threat_id = "2147834299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xutaseboniwilikivolocidizawijubihecivonod" wide //weight: 2
        $x_2_2 = "mosezogonufozudipejasedo" wide //weight: 2
        $x_2_3 = "befubuvawe" wide //weight: 2
        $x_2_4 = "uzutijagofedofup" wide //weight: 2
        $x_2_5 = "ruzoxotozipad" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_SmokeLoader_Z_2147943407_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SmokeLoader.Z!MTB"
        threat_id = "2147943407"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 18 00 00 00 6b c8 00 8b 54 0d dc 83 c2 30 b8 01 00 00 00 6b c8 11 8b 45 08 88 14 08}  //weight: 1, accuracy: High
        $x_1_2 = {68 b8 33 41 00 ff 15 30 30 41 00 89 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

