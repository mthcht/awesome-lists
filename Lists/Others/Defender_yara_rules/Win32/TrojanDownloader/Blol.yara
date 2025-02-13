rule TrojanDownloader_Win32_Blol_C_2147619595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Blol.C"
        threat_id = "2147619595"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Blol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 b8 0b 00 00 e8 ?? ?? 00 00 6a 00 ff 75 ec e8 ?? ?? 00 00 68 85 00 00 00 68 ?? ?? 40 00 e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {74 07 6a 00 e8 ?? ?? 00 00 6a ?? 68 ?? ?? 40 00 6a ff 6a ff e8 ?? ?? ff ff 50 6a 18 68 ?? ?? 40 00 c7 45 a4 00 00 00 00 c7 45 a8 00 00 00 00 c7 45 ac 00 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "echo olha > C:\\TEMP\\blolor" ascii //weight: 1
        $x_1_4 = "shutdown -r -f -t 10 -c \"Erro Interno do Windows" ascii //weight: 1
        $x_1_5 = "MicrosoftOptimizationer" ascii //weight: 1
        $x_2_6 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 65 6e 20 5c 53 79 73 74 65 6d 33 32 5c 68 61 68 61 68 61 [0-5] 6a 75 6d 70 65 72 72 2e 65 78 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

