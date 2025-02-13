rule TrojanDownloader_Win32_Whynxy_A_2147600671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Whynxy.A"
        threat_id = "2147600671"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Whynxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Internet Explorer\\iexplore.exe" ascii //weight: 1
        $x_1_2 = "services.dll" ascii //weight: 1
        $x_1_3 = "DnldMTse" ascii //weight: 1
        $x_1_4 = "XhywWhn" ascii //weight: 1
        $x_1_5 = "GCrhjo" ascii //weight: 1
        $x_1_6 = "--AaB03x" ascii //weight: 1
        $x_1_7 = "name=\"datei\";" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

