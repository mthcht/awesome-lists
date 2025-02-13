rule TrojanDownloader_PowerShell_Falsip_C_2147724927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Falsip.C"
        threat_id = "2147724927"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Falsip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = {3d 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 2b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 5b 00 62 00 79 00 74 00 65 00 5d 00 39 00 32 00 2b 00 27 00 31 00 35 00 [0-32] 2e 00 6a 00 73 00 27 00 3b 00 28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 00 74 00 70 00 27 00 2b 00 27 00 73 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".jse',$d);Invoke-Item $d;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Falsip_D_2147729378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Falsip.D"
        threat_id = "2147729378"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Falsip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 20 00 24 00 64 00 3d 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 2b 00 27 00 5c 00 [0-32] 2e 00 6a 00 73 00 27 00 3b 00 69 00 65 00 78 00 28 00 24 00 65 00 6e 00 76 00 3a 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-48] 2e 00 [0-6] 2f 00 [0-32] 2e 00 6a 00 73 00 27 00 2c 00 24 00 64 00 29 00 3b 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 49 00 74 00 65 00 6d 00 20 00 24 00 64 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

