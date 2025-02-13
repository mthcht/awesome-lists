rule TrojanDownloader_PowerShell_Powersploit_G_2147725479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Powersploit.G"
        threat_id = "2147725479"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Powersploit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-128] 2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 6d 00 61 00 66 00 69 00 61 00 2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 70 00 6c 00 6f 00 69 00 74 00 2f 00 6d 00 61 00 73 00 74 00 65 00 72 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Powersploit_H_2147725480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Powersploit.H"
        threat_id = "2147725480"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Powersploit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-128] 2f 00 70 00 65 00 65 00 77 00 70 00 77 00 2f 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 63 00 6d 00 64 00 75 00 6d 00 70 00 2f 00 6d 00 61 00 73 00 74 00 65 00 72 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_Powersploit_I_2147725481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Powersploit.I"
        threat_id = "2147725481"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Powersploit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-128] 2f 00 6d 00 61 00 74 00 74 00 69 00 66 00 65 00 73 00 74 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 70 00 6c 00 6f 00 69 00 74 00 2f 00 6d 00 61 00 73 00 74 00 65 00 72 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

