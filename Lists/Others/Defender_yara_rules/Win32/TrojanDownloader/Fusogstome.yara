rule TrojanDownloader_Win32_Fusogstome_A_2147951207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fusogstome.A!dha"
        threat_id = "2147951207"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fusogstome"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://drive.google.com/" ascii //weight: 1
        $x_1_2 = "fuslogvw.exe" ascii //weight: 1
        $x_1_3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

