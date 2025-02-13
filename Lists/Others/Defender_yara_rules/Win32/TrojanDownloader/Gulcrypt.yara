rule TrojanDownloader_Win32_Gulcrypt_B_2147691634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gulcrypt.B"
        threat_id = "2147691634"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 1d 76 ?? 83 f8 1f 73 ?? 83 c0 4a a3 ?? ?? ?? ?? 50 68 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 0c 68}  //weight: 2, accuracy: Low
        $x_1_2 = ".ru/sys" ascii //weight: 1
        $x_1_3 = ".ru/rar" ascii //weight: 1
        $x_1_4 = "c:\\teemp" ascii //weight: 1
        $x_1_5 = "pipec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

