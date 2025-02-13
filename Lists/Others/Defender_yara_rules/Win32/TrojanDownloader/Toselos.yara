rule TrojanDownloader_Win32_Toselos_A_2147629549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Toselos.A"
        threat_id = "2147629549"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Toselos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 58 6a 04 8b 45 fc e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 0c}  //weight: 1, accuracy: Low
        $x_1_2 = "http://%s/tools.txt" ascii //weight: 1
        $x_1_3 = "taskkill /F /PID %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

