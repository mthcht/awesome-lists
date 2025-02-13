rule TrojanDownloader_Win32_Downkuary_B_2147712306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Downkuary.B!bit"
        threat_id = "2147712306"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Downkuary"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xiaobingdou.com" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\%s\\jihuo;64:HKEY_CURRENT_USER\\Software\\%s\\jihuo" wide //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\YeaInstaller;64:HKEY_CURRENT_USER\\Software\\YeaInstaller" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\yeaplayer;64:HKEY_CURRENT_USER\\Software\\yeaplayer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Downkuary_C_2147712625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Downkuary.C!bit"
        threat_id = "2147712625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Downkuary"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xiaobingdou.com/down" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\%s\\jihuo;64:HKEY_CURRENT_USER\\Software\\%s\\jihuo" wide //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\YeaInstaller" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Downkuary_D_2147716560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Downkuary.D!bit"
        threat_id = "2147716560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Downkuary"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TheWorld.ini" wide //weight: 1
        $x_1_2 = {64 00 6c 00 2e 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 62 00 61 00 69 00 64 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 6e 00 69 00 6f 00 6e 00 2f 00 67 00 65 00 74 00 62 00 64 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2e 00 70 00 68 00 70 00 3f 00 74 00 6e 00 3d 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_10_3 = "GM_downloading" wide //weight: 10
        $x_10_4 = "d1.kuai8.com/setup/kuai8_rjaz.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

