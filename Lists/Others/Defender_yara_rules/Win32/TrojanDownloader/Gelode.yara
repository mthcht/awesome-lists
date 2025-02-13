rule TrojanDownloader_Win32_Gelode_A_2147658967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gelode.A"
        threat_id = "2147658967"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gelode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 30 88 44 3e ff 8a 41 fe}  //weight: 1, accuracy: High
        $x_1_2 = "073110116101114110101116082101097100070105108101" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

