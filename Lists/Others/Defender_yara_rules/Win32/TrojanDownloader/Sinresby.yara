rule TrojanDownloader_Win32_Sinresby_A_2147651562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinresby.A"
        threat_id = "2147651562"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinresby"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 75 6e 64 6c 6c 2e 64 6c 6c 00 72 75 6e}  //weight: 1, accuracy: High
        $x_1_2 = {73 69 6e 67 6c 65 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 73 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = "BlackMoon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Sinresby_B_2147707554_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinresby.B"
        threat_id = "2147707554"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinresby"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 26 6b 3d 00 26 6f 3d 00 26 43 3d 00 26 75 3d 00 26 64 3d 00 26 76 3d 00 6d 3d 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = "Select MACAddress From Win32_NetworkAdapter WHERE PNPDeviceID LIKE \"%PCI%" ascii //weight: 1
        $x_1_3 = {62 6c 61 63 6b 6d 6f 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

