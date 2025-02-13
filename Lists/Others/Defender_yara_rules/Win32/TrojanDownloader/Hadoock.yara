rule TrojanDownloader_Win32_Hadoock_A_2147709695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hadoock.A!bit"
        threat_id = "2147709695"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hadoock"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\tmp\\svhost.exe" wide //weight: 2
        $x_2_2 = "\\svhost.backup" wide //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_4 = "/updaterestart" wide //weight: 1
        $x_1_5 = {ba 0b 00 00 00 8b 38 83 c9 ff 89 13 8b 55 dc 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 53 04 50 89 45 d0 89 4b 08 8b 4d e4 89 4b 0c ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

