rule Worm_Win32_NeksMiner_AMTB_2147964157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/NeksMiner!AMTB"
        threat_id = "2147964157"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "NeksMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://kr1s.ru/javarx.dat" ascii //weight: 1
        $x_1_2 = "http://zcop.ru/javarx2.dat" ascii //weight: 1
        $x_1_3 = "/kr1s./rucop./zcop./jpgo." ascii //weight: 1
        $x_1_4 = "/c taskkill /f /im NsCpuCNMiner*" ascii //weight: 1
        $x_1_5 = "\\javarx.exe" ascii //weight: 1
        $x_1_6 = "stratum+tcp://pool" ascii //weight: 1
        $n_100_7 = "Uninst.exe" ascii //weight: -100
        $n_100_8 = "Uninstaller.exe" ascii //weight: -100
        $n_100_9 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

