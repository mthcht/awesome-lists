rule TrojanDownloader_Win32_BulbSoup_A_2147831980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BulbSoup.A!dha"
        threat_id = "2147831980"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BulbSoup"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "curl.exe -k" wide //weight: 100
        $x_100_2 = "ufowdauczwpa4enmzj2yyf7m4cbsjcaxxoyeebc2wdgzwnhvwhjf7iid.onion" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

