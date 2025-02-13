rule TrojanDownloader_Win32_Wxpse_2147607609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wxpse"
        threat_id = "2147607609"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wxpse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "http://b3.998flash.cn/download/" ascii //weight: 5
        $x_5_2 = {77 78 70 53 65 74 75 70 00 00}  //weight: 5, accuracy: High
        $x_1_3 = {61 72 75 6e 2e 72 65 67 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 65 67 65 64 69 74 2e 65 78 65 20 2f 73 20}  //weight: 1, accuracy: Low
        $x_1_4 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

