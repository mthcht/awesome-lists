rule TrojanDownloader_Win32_Grameyoon_A_2147649083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Grameyoon.A"
        threat_id = "2147649083"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Grameyoon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 6f 6d 6f 63 65 6c 6c 2e 63 6f 6d 2f 6c 6f 67 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6d 61 63 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 70 64 61 74 65 2e 6d 6f 6d 6f 63 65 6c 6c 2e 63 6f 6d 2f 64 77 6e 2f 6c 6f 67 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 4c 49 4d 20 61 67 65 6e 74 20 6d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Grameyoon_B_2147649394_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Grameyoon.B"
        threat_id = "2147649394"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Grameyoon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 6f 6d 6f 63 65 6c 6c 2e 63 6f 6d 2f 6c 6f 67 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6d 61 63 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 69 6e 20 6d 61 6e 61 67 65 72 20 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 36 65 36 46 34 34 37 34 5d 00 00 26 63 6f 64 65 3d 30 30 30 33 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 61 6e 75 73 00 77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

