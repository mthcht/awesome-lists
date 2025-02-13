rule TrojanDownloader_Win32_VidarStealer_SIB_2147816793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VidarStealer.SIB!MTB"
        threat_id = "2147816793"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ControlOfs0040000000000A34" ascii //weight: 1
        $x_1_2 = "D$LPkD$XdPV" ascii //weight: 1
        $x_1_3 = {8b d8 8b 45 ?? 8b 00 03 45 ?? 03 d8 [0-32] 2b d8 8b 45 00 89 18 [0-32] 8b (45|55) 00 31 (18|02) [0-32] 8b d8 [0-32] 2b d8 [0-32] 8b 45 01 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

