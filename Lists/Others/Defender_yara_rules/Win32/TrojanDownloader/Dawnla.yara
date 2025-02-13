rule TrojanDownloader_Win32_Dawnla_A_2147744427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dawnla.A!MSR"
        threat_id = "2147744427"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dawnla"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 00 78 00 35 00 33 00 [0-2] 36 00 38 00 [0-2] 36 00 [0-2] 35 00 [0-2] 36 00 [0-2] 43 00 [0-2] 36 00 [0-2] 43 00 34 00 [0-2] 35 00 [0-2] 37 00 [0-2] 38 00 36 00 [0-2] 35 00 36 00 33 00 [0-2] 37 00 35 00 37 00 [0-2] 34 00 36 00 [0-2] 35 00 32 00 38 00 [0-2] 32 00 32 00 [0-2] 36 00 [0-2] 33 00 [0-2] 36 00 44 00 [0-2] 36 00 34 00 [0-2] 32 00 32 00 32 00 [0-2] 43 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

