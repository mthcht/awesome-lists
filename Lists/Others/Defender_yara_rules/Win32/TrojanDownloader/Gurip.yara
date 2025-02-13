rule TrojanDownloader_Win32_Gurip_A_2147685158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gurip.A"
        threat_id = "2147685158"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gurip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 48 00 54 00 54 00 50 00 [0-16] 47 00 45 00 54 00 [0-16] 4f 00 70 00 65 00 6e 00 [0-16] 73 00 65 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_2_2 = "cmd.exe /c REG ADD HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-16] 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2e 00 6e 00 6f 00 2d 00 69 00 70 00 2e 00 6f 00 72 00 67 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

