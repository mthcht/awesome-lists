rule TrojanDownloader_Win32_Sock5Systemz_MK_2147955806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sock5Systemz.MK!MTB"
        threat_id = "2147955806"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sock5Systemz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {8d 14 38 8b ca 8d 41 01 89 45 f0 8a 01 41 84 c0}  //weight: 15, accuracy: High
        $x_10_2 = {8b 5c 24 38 84 c0 59 6a 01 0f b6 db 58 0f 45 d8}  //weight: 10, accuracy: High
        $x_3_3 = "gpt=%.8x&inc=%d&advizor=%d&box=%d&hp=%x&lp=%x&line=%d&os=%d.%d.%04d&flag=%d&itd=%d" ascii //weight: 3
        $x_2_4 = ".\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

