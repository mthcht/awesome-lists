rule TrojanDownloader_Win32_StackPower_A_2147848156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/StackPower.A!dha"
        threat_id = "2147848156"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "StackPower"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Intel\\UNP\\ProgramUpdates\\openexplorer.exe" wide //weight: 1
        $x_1_2 = "-Description 'UserOOEBroker Update'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

