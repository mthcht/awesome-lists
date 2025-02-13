rule TrojanDownloader_Win32_BazaarLoader_MB_2147767090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BazaarLoader.MB!MTB"
        threat_id = "2147767090"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 3d ec 8d 76 02 8a ca b0 ?? c0 e9 ?? 80 e2 ?? 3a c1 1a c0 24 ?? 04 ?? 02 c1 88 46 fe b0 ?? 3a c2 1a c0 47 24 ?? 04 ?? 02 c2 88 46 ff 83 ff ?? 72 cd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

