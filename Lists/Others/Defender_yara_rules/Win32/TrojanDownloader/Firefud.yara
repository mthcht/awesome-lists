rule TrojanDownloader_Win32_Firefud_A_2147659625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Firefud.A"
        threat_id = "2147659625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Firefud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CCljulioSpam" ascii //weight: 1
        $x_1_2 = {75 00 73 00 65 00 72 00 73 00 5c 00 66 00 62 00 73 00 5c 00 6d 00 79 00 20 00 70 00 72 00 6f 00 79 00 65 00 63 00 74 00 73 00 5c 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 73 00 5c 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 20 00 66 00 75 00 64 00 20 00 [0-16] 5c 00 70 00 72 00 6f 00 79 00 65 00 63 00 74 00 6f 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "http://www.powerdomein.nl/nld/administrator/backups/firewallc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

