rule TrojanDownloader_Win32_Throng_A_2147622059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Throng.A"
        threat_id = "2147622059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Throng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "expand=%u&id=%s&version=%u" ascii //weight: 1
        $x_1_2 = "<([a-z_]+)>(?*)</([a-z_]+)>" ascii //weight: 1
        $x_1_3 = "%s\\ibm.txt" ascii //weight: 1
        $x_1_4 = "src=%d&password=%s" ascii //weight: 1
        $x_1_5 = "&code=%s&key=%s" ascii //weight: 1
        $x_1_6 = "%d|%d|%d|%d|%d" ascii //weight: 1
        $x_1_7 = "Cookie: %s=%s" ascii //weight: 1
        $x_1_8 = "%d,%d" ascii //weight: 1
        $x_1_9 = "\\dnf.exe" ascii //weight: 1
        $x_1_10 = "http://209.11.244.51/p.php?n=m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

