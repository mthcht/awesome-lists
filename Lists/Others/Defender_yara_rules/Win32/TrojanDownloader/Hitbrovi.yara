rule TrojanDownloader_Win32_Hitbrovi_A_2147696641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hitbrovi.A!dha"
        threat_id = "2147696641"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitbrovi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Low Rights\\ElevationPolicy\\{5852F5ED-8BF4-11D4-A245-0080C6F74284}" wide //weight: 2
        $x_2_2 = "EXE_NAMEAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide //weight: 2
        $x_2_3 = "EXE_URLAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide //weight: 2
        $x_2_4 = "SCOUT_TEMP_NAMEAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide //weight: 2
        $x_2_5 = "DOC_TEMP_NAMEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide //weight: 2
        $x_2_6 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

