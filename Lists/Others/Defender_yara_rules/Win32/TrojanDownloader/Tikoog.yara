rule TrojanDownloader_Win32_Tikoog_A_2147726566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tikoog.A!ms"
        threat_id = "2147726566"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tikoog"
        severity = "Critical"
        info = "ms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 8b 55 ?? 8b 02 99 f7 f9 0f af 45 ?? ?? 45 ?? ?? 45 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {99 f7 f9 03 45 ?? 89 45 ?? eb cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

