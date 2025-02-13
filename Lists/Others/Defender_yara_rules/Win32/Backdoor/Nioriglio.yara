rule Backdoor_Win32_Nioriglio_A_2147697015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nioriglio.A"
        threat_id = "2147697015"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nioriglio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {69 00 6c 00 69 00 6c 00 69 00 2e 00 72 00 67 00 2e 00 72 00 6f 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "\\winIogons.exe" wide //weight: 1
        $x_1_3 = "\\iexpIore.exe" wide //weight: 1
        $x_1_4 = "Img_DownTorrentAppClick" ascii //weight: 1
        $x_1_5 = "\\Img\\None.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Nioriglio_A_2147697015_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nioriglio.A"
        threat_id = "2147697015"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nioriglio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".rg.ro" wide //weight: 1
        $x_1_2 = {22 00 20 00 64 00 69 00 72 00 3d 00 69 00 6e 00 20 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 6c 00 6c 00 6f 00 77 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 69 00 65 00 78 00 [0-2] 70 00 49 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 73 00 79 00 73 00 66 00 61 00 64 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 77 00 69 00 6e 00 49 00 6f 00 67 00 6f 00 6e 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 [0-16] 53 00 74 00 61 00 72 00 74 00 55 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

