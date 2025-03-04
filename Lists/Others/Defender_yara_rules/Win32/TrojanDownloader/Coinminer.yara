rule TrojanDownloader_Win32_Coinminer_OS_2147725165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Coinminer.OS!bit"
        threat_id = "2147725165"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 64 00 62 00 6c 00 6f 00 63 00 6b 00 2e 00 61 00 6b 00 6b 00 65 00 6c 00 73 00 2e 00 72 00 75 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFile, %site%, winhost.exe" ascii //weight: 1
        $x_1_3 = "FileSetAttrib, +H+S" ascii //weight: 1
        $x_1_4 = "FileCreateDir, %Appdata%\\Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Coinminer_QB_2147726120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Coinminer.QB!bit"
        threat_id = "2147726120"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 74 74 70 3a 2f 2f 69 6e 6e 66 69 6e 69 74 69 2e 75 63 6f 7a 2e 6e 65 74 2f [0-16] 2e 7a 69 70}  //weight: 3, accuracy: Low
        $x_2_2 = {46 69 6c 65 44 65 6c 65 74 65 2c 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 76 62 73}  //weight: 2, accuracy: Low
        $x_2_3 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName" ascii //weight: 2
        $x_1_4 = "https://iplogger.com" ascii //weight: 1
        $x_1_5 = "Select * from Win32_Processor" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\AVAST Software" ascii //weight: 1
        $x_1_7 = "C:\\ProgramData\\ESET" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

