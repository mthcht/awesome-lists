rule TrojanDownloader_Win32_Wibimo_2147647272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wibimo"
        threat_id = "2147647272"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wibimo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 02 c6 01 6d c6 41 01 73 5e a1 ?? ?? ?? ?? 85 c0 75 0e 0f 31 03 c2 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 05 c3 9e 26 00}  //weight: 3, accuracy: Low
        $x_3_2 = {47 23 f8 8d b4 3d f0 fe ff ff 8a 16 0f b6 ca 03 4d f4 23 c8 89 4d f4 8d 8c 0d f0 fe ff ff 8a 19 88 11 8b 55 08 88 1e 0f b6 09 8b 75 f8 0f b6 db 03 cb 23 c8 8a 8c 0d f0 fe ff ff 03 d6 30 0a 46 3b 75 0c 89 75 f8 7c b8}  //weight: 3, accuracy: High
        $x_1_3 = "Global\\sp_runned" ascii //weight: 1
        $x_1_4 = "action=allow program=\"%windir%\\system32\\rundll32.exe\"" ascii //weight: 1
        $x_1_5 = "NETSH advfirewall FIREWALL add rule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

