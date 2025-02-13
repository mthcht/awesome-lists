rule TrojanDownloader_Win32_Meteorite_A_2147728102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Meteorite.A!bit"
        threat_id = "2147728102"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteorite"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MeteoriteDownloader" ascii //weight: 2
        $x_2_2 = "//Meteorite\\\\" wide //weight: 2
        $x_1_3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_4 = "SbieDll.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

