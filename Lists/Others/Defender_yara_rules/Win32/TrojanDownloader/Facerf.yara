rule TrojanDownloader_Win32_Facerf_A_2147630494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Facerf.A"
        threat_id = "2147630494"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Facerf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "*exe-exe*" ascii //weight: 1
        $x_1_2 = {67 73 70 63 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 01 0f 85 ?? ?? ?? ?? 68 b8 0b 00 00 e8}  //weight: 1, accuracy: Low
        $x_2_4 = {3d 00 c8 00 00 0f 86 ?? ?? ?? ?? 6a 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

