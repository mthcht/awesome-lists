rule TrojanDownloader_Win32_NetWired_SIB_2147812261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/NetWired.SIB!MTB"
        threat_id = "2147812261"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWired"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DE_KmnnectZ" ascii //weight: 1
        $x_1_2 = "aneT.DLL" ascii //weight: 1
        $x_1_3 = {f7 e2 c1 e8 ?? 89 d1 81 e2 ?? ?? ?? ?? c1 e9 ?? 8d 14 92 01 c2 89 c8 83 c8 ?? 88 07 89 d0 83 f9 01 83 df ff c1 e8 ?? 81 e2 ?? ?? ?? ?? 09 c1 83 c8 ?? 88 07 8d 04 92 8d 14 92 83 f9 01 83 df ff c1 e8 ?? 81 e2 ?? ?? ?? ?? 09 c1 83 c8 ?? 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

