rule TrojanDownloader_Win32_Tonfled_A_2147662948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tonfled.A"
        threat_id = "2147662948"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tonfled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TG=%d&CP=%d&Key=%d&JC=%d&YP=%02x&second=%d&lj=%s" ascii //weight: 1
        $x_1_2 = {8a 10 80 f2 9c 88 10 40 3b c1 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {81 fb 9f 86 01 00 0f 8d aa 01 00 00 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

