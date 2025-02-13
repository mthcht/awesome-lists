rule TrojanDownloader_Win32_Tonnejoom_A_2147705803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tonnejoom.A"
        threat_id = "2147705803"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tonnejoom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "joomla.eduhi.at/vs28/schule/administrator/components/com_phocagallery/c.exe" ascii //weight: 2
        $x_2_2 = "w.schweizerhof-wetzikon.ch/images/rtucrtmirumctrutbitueriumxe/ivotyimoyctorieotcmir.exe" ascii //weight: 2
        $x_1_3 = {8b c8 83 e1 03 8a 0c 11 30 88 ?? ?? ?? 00 40 83 f8 52 72 ec b8 ?? ?? ?? 00 8d 48 01 90 8a 10 40 84 d2 75 f9}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 05 6a 60 e8 ?? ?? 00 00 8d 14 40 c1 e2 08 bf ff ff ff 7f 6a 01 2b fa e8}  //weight: 1, accuracy: Low
        $x_1_5 = {85 f6 76 12 8b ff 8b d0 83 e2 03 8a 14 0a 30 14 38 40 3b c6 72 f0 8b c7}  //weight: 1, accuracy: High
        $x_1_6 = {eb 02 33 c9 8b c3 c1 e8 08 8b d3 88 19 c1 eb 18 88 41 01 c1 ea 10 33 c0 88 59 03 88 51 02}  //weight: 1, accuracy: High
        $x_1_7 = "/puretonnel.net/3desonnel.js" ascii //weight: 1
        $x_1_8 = "www.easycounter.com/counter.php?vtrtvrvtrtvertvr" ascii //weight: 1
        $x_1_9 = ".com/counter.php?tcrcrcerererwbvbbrtdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

