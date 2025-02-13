rule TrojanDownloader_Win32_Mutisedow_A_2147814529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mutisedow.A"
        threat_id = "2147814529"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mutisedow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateObject(\"WindowsInstaller.Installer\")" ascii //weight: 2
        $x_2_2 = "UILevel=2" ascii //weight: 2
        $x_2_3 = "InstallProduct\"http" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

