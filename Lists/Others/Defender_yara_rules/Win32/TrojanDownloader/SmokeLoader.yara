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

