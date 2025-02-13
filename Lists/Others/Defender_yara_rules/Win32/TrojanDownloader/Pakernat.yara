rule TrojanDownloader_Win32_Pakernat_A_2147600892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pakernat.A"
        threat_id = "2147600892"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pakernat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 00 00 ad de 8b fe 66 ba ce fa 8a 06 46 32 c2 83 ea 06 aa 83 c2 f9 e2 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

