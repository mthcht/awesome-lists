rule TrojanDownloader_Win32_Pnimop_A_2147619598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pnimop.A"
        threat_id = "2147619598"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pnimop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "{33333333-AAAA-OOOO-4444-DFKLJKJDFLJD}" ascii //weight: 10
        $x_10_2 = "Mozilla" ascii //weight: 10
        $x_10_3 = "%serial%" ascii //weight: 10
        $x_10_4 = "MyWinPop" ascii //weight: 10
        $x_10_5 = {56 53 56 56 68 2c 01 00 00 68 90 01 00 00 56 57 68 00 00 cf 00 50 50 56 89 1d ?? ?? 43 00 ff 15 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_1_6 = "Connected: %02i:%02i:%02i" ascii //weight: 1
        $x_1_7 = {00 32 66 6b 66 6a 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = "url_download" ascii //weight: 1
        $x_1_9 = "Opening modem port..." ascii //weight: 1
        $x_1_10 = {00 31 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

