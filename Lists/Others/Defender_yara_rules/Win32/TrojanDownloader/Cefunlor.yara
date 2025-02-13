rule TrojanDownloader_Win32_Cefunlor_A_2147692422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cefunlor.A"
        threat_id = "2147692422"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cefunlor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 47 1c ba 00 00 01 00 e8 ?? ?? ?? ?? c7 47 10 90 5f 01 00 8d 47 08 ba ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {69 6e 66 5f 66 61 63 65 5f 63 75 ?? 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_3 = "zaybxjkqrclmwnopdtustefghiuv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

