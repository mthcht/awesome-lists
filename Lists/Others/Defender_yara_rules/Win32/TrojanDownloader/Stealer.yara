rule TrojanDownloader_Win32_Stealer_HSG_2147816928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stealer.HSG!MSR"
        threat_id = "2147816928"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 [0-32] 72 73 73 2e 66 62 76 69 64 63 64 6e 2e 63 6f 6d 2f 64 6c 2f 73 65 65 64 2f 20 2d 4f 75 74 46 69 6c 65 20 27 25 61 70 70 64 61 74 61 25 5c 73 2d 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" ascii //weight: 1
        $x_1_3 = "C:\\TEMP\\config.cmd" ascii //weight: 1
        $x_1_4 = "del /F /Q \"%appdata%\\s-installer.exe" ascii //weight: 1
        $x_1_5 = "C:\\Users\\OS\\Desktop\\scseed\\Release\\scseed.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

