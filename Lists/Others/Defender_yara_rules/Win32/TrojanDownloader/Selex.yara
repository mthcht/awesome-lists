rule TrojanDownloader_Win32_Selex_A_2147603617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Selex.A"
        threat_id = "2147603617"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Selex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "543"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "key=merdasecc" ascii //weight: 100
        $x_100_2 = "URLDownloadToFileA" ascii //weight: 100
        $x_100_3 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 100
        $x_100_4 = "/c del " ascii //weight: 100
        $x_100_5 = "Faslane Downloader 3.34b" wide //weight: 100
        $x_1_6 = "CreateStreamOnHGlobal" ascii //weight: 1
        $x_1_7 = "%s?param=%d" ascii //weight: 1
        $x_1_8 = "Host: %s" ascii //weight: 1
        $x_1_9 = "POST %s HTTP/1." ascii //weight: 1
        $x_1_10 = "Content-type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_11 = "Content-length: 14" ascii //weight: 1
        $x_20_12 = "BINARY" ascii //weight: 20
        $x_20_13 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zone" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_100_*) and 2 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

