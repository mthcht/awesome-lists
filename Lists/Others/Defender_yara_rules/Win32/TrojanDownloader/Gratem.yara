rule TrojanDownloader_Win32_Gratem_A_2147682043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gratem.A"
        threat_id = "2147682043"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gratem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f9 eb 75 ?? 0f b6 4a 01 33 c8 80 f9 02 75 ?? 0f b6 4a 02 33 c8 80 f9 cc 75 ?? 0f b6 4a 03 33 c8 80 f9 f1 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

