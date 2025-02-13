rule TrojanDownloader_Win32_Debaox_A_2147726402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Debaox.A!ms"
        threat_id = "2147726402"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Debaox"
        severity = "Critical"
        info = "ms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 14 18 8a 12 ?? ?? 80 f2 ?? 8d 0c 18 88 11 ?? ?? 40 3d ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

