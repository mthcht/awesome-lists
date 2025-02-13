rule TrojanDownloader_Win32_Abcexp_A_2147607733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Abcexp.A"
        threat_id = "2147607733"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Abcexp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "windows\\system32\\exp1orer.exe" ascii //weight: 5
        $x_2_2 = "217.17.41.93" ascii //weight: 2
        $x_2_3 = {41 42 43 44 45 46 47 48 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 42 43 44 45 46 47 48 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "DosCommand1NewLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

