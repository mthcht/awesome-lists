rule TrojanDownloader_Win32_Grepise_A_2147727980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Grepise.A!bit"
        threat_id = "2147727980"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Grepise"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 3e 8b cf 2c ?? 34 ?? 88 04 3e 46 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 3b f1 72 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be c1 83 f0 ?? 83 c0 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

