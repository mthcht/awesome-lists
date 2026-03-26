rule Worm_Win32_Rahiwi_AMTB_2147965639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rahiwi!AMTB"
        threat_id = "2147965639"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rahiwi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Next varian will be released a.s.a.p" ascii //weight: 1
        $x_1_2 = "Tiwi.exe" ascii //weight: 1
        $x_1_3 = "My present to Tiwi" ascii //weight: 1
        $x_1_4 = "_CIcosadj_fptan" ascii //weight: 1
        $x_1_5 = "W32/TiwiA" ascii //weight: 1
        $x_1_6 = "It's Free..." ascii //weight: 1
        $x_1_7 = "}Endmdiv_m64" ascii //weight: 1
        $n_100_8 = "Uninst.exe" ascii //weight: -100
        $n_100_9 = "Uninstaller.exe" ascii //weight: -100
        $n_100_10 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

