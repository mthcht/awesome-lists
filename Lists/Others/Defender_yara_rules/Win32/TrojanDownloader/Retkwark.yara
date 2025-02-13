rule TrojanDownloader_Win32_Retkwark_A_2147705852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Retkwark.A"
        threat_id = "2147705852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Retkwark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "w.apostar.bz/ar_to.exe" wide //weight: 4
        $x_4_2 = "ww.islamicstudies.info/ar_to.exe" wide //weight: 4
        $x_2_3 = "ww.djmartin.cz/foto" wide //weight: 2
        $x_1_4 = "ar_in.exe" wide //weight: 1
        $x_1_5 = "ar_to.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

