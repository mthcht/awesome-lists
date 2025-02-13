rule TrojanDownloader_Win32_Cawhotmer_A_2147638811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cawhotmer.A"
        threat_id = "2147638811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cawhotmer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "geradoaviso\\" wide //weight: 1
        $x_1_2 = {2f 00 73 00 70 00 6c 00 75 00 73 00 2f 00 [0-2] 2e 00 61 00 73 00 70 00 3f 00 6d 00 6b 00 6e 00 61 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

