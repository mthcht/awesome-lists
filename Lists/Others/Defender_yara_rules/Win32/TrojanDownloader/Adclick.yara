rule TrojanDownloader_Win32_Adclick_2147618731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adclick"
        threat_id = "2147618731"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adclick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "microsoft.loginapp.com/update" ascii //weight: 2
        $x_2_2 = {63 6e 74 2e 61 64 68 61 72 75 2e 63 6f 6d 2f 61 64 75 6c 74 2e 70 68 70 3f 63 70 69 64 3d 6e 76 00 53 6f 66 74 77 61 72 65 5c 00 00 00 6f 70 65 6e}  //weight: 2, accuracy: High
        $x_1_3 = "%%WINDOWS\\%sprv.imb" ascii //weight: 1
        $x_1_4 = {25 41 46 46 49 4c 44 41 54 41 00 00 43 6c 69 63 6b 55 72 6c}  //weight: 1, accuracy: High
        $x_1_5 = {00 63 6c 69 63 6b 63 79 63 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

