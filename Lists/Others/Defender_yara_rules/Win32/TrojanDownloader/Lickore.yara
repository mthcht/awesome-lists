rule TrojanDownloader_Win32_Lickore_B_2147657736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lickore.B"
        threat_id = "2147657736"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lickore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? b8 ?? ?? ?? ?? e8 [0-16] ff [0-5] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ?? ba 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "down.tmqrhks.com/dist" ascii //weight: 1
        $x_1_4 = {54 52 41 43 45 [0-16] 50 55 54 [0-16] 43 4f 4e 4e 45 43 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

