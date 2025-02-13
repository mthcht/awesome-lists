rule TrojanDownloader_Win32_Seveto_A_2147654502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seveto.A"
        threat_id = "2147654502"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seveto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b c8 8a 01 34 ?? 88 45 ?? 8b c1 8d 55 ?? b9 01 00 00 00 e8 ?? ?? ff ff 8b c3 25 ff 03 00 80 79 07 48 0d 00 fc ff ff 40 85 c0 75 07 6a ?? e8 ?? ?? ff ff 43 4e 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 8b 45 fc e8 ?? ?? ff ff 50 6a 00 6a 02 68 10 01 00 00 68 ff 01 0f 00 56 53 8b 45 f8 50 e8 ?? ?? ff ff 8b d8 33 c0 89 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Seveto_A_2147660061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seveto.gen!A"
        threat_id = "2147660061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seveto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04}  //weight: 1, accuracy: High
        $x_1_2 = "E494VzSTjLNhF9L" ascii //weight: 1
        $x_1_3 = "G9R2V3MTMeBMv9G+/B" ascii //weight: 1
        $x_1_4 = "K9kCOl9/owxBAT1vDOc8j0P" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\svcs.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

