rule TrojanDownloader_Win32_Startpage_CA_2147640533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Startpage.CA"
        threat_id = "2147640533"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 83 f9 64 72 ef 68 d0 07 00 00 ff 15 ?? ?? ?? ?? 39 5d f0 75 0a 68 03 40 00 80}  //weight: 1, accuracy: Low
        $x_1_2 = "%s\\1228.tmp" ascii //weight: 1
        $x_1_3 = {2e 37 36 35 33 32 31 2e 69 6e 66 6f 3a ?? ?? ?? ?? 2f 73 6d 73 2f 78 78 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

