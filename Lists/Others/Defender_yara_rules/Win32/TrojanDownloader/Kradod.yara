rule TrojanDownloader_Win32_Kradod_B_2147658695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kradod.B"
        threat_id = "2147658695"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kradod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab b9 08 00 00 00 8d 7c ?? ?? f3 ab 8d 44 ?? ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 03 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 64 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "%sUID=%s&OSV=%s&IEV=%s&VER=%s" ascii //weight: 1
        $x_1_4 = "UpExeUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

