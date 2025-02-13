rule TrojanDownloader_Win32_Copia_A_2147622428_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Copia.A"
        threat_id = "2147622428"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Copia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\copia_bho\\" wide //weight: 1
        $x_1_2 = "API-Guide test program" wide //weight: 1
        $x_1_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {32 2e 30 33 00 55 50 58 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

