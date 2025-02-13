rule TrojanDownloader_Win32_Bitsaload_MK_2147772085_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bitsaload.MK!MTB"
        threat_id = "2147772085"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitsaload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 [0-10] 2e 65 78 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 [0-10] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = "powershell -command Import-Module BitsTransfer; Start-BitsTransfer" ascii //weight: 10
        $x_10_3 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f [0-18] 2f 50 68 6f 65 6e 69 78 4d 69 6e 65 72 2e 65 78 65 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 [0-10] 2e 65 78 65 2c [0-10] 2e 65 78 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

