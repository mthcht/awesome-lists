rule TrojanDownloader_Win32_Loiketnoi_A_2147896387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Loiketnoi.A!MTB"
        threat_id = "2147896387"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Loiketnoi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 00 89 c2 c7 44 24 08 10 00 00 00 8d 45 ?? 89 44 24 04 89 14 24 a1 ?? ?? 40 00 ff d0 83 ec 0c 85 c0 ?? ?? c7 04 24 ?? ?? ?? ?? a1 ?? ?? 40 00 ff d0 83 ec 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

