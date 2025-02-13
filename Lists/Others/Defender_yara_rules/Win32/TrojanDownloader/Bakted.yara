rule TrojanDownloader_Win32_Bakted_A_2147626436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bakted.A"
        threat_id = "2147626436"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bakted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\rundll32.exe %s%s,Set" ascii //weight: 1
        $x_1_2 = {25 64 25 64 25 64 64 6f 6e 2e 64 6c 6c 00 00 00 64 65 6c 20 25 30}  //weight: 1, accuracy: High
        $x_1_3 = {64 2e 62 61 74 00 00 00 79 61 68 6f 6f 21 00 00 25 73 2c 53 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

