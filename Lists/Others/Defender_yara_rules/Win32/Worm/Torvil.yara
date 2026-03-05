rule Worm_Win32_Torvil_AMTB_2147964156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Torvil!AMTB"
        threat_id = "2147964156"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Torvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Location:File://torvil.exe" ascii //weight: 1
        $x_1_2 = "torvil.pif" ascii //weight: 1
        $x_1_3 = "OneLevelDeeper\\TorvilDB" ascii //weight: 1
        $x_1_4 = "spoolux.exe" ascii //weight: 1
        $x_1_5 = "!File://torvil.exe" ascii //weight: 1
        $n_100_6 = "Uninst.exe" ascii //weight: -100
        $n_100_7 = "Uninstaller.exe" ascii //weight: -100
        $n_100_8 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

