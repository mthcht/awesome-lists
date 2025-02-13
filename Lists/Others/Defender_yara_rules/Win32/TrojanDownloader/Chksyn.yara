rule TrojanDownloader_Win32_Chksyn_A_2147601047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chksyn.A"
        threat_id = "2147601047"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 06 6a 10 88 45 fd 8d 45 fc 6a 00 50 e8 ?? ?? 00 00 8b 4d ?? 83 c4 0c 34 ?? ff 45 ?? 46 53 88 01 46 ff d7}  //weight: 4, accuracy: Low
        $x_4_2 = {8b 45 fc 35 11 ca ad de 5b c9 c3}  //weight: 4, accuracy: High
        $x_4_3 = {56 ff d7 6a 05 8d 74 06 01 68 ?? ?? ?? ?? 56 e8 ?? ?? 00 00 83 c4 0c 85 c0 74 c4}  //weight: 4, accuracy: Low
        $x_2_4 = "\\\\.\\pipe\\NTSvcLoad" ascii //weight: 2
        $x_2_5 = "id=%x&ver=%d.%d&data=%s" ascii //weight: 2
        $x_1_6 = "ntminilrd" wide //weight: 1
        $x_1_7 = "ntradldr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Chksyn_A_2147602232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chksyn.gen!A"
        threat_id = "2147602232"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 53 56 57 6a 04 be 00 30 00 00 56 ff 35 00 20 11 13 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 ae d0 16 ab e8 ?? 00 00 00 50 e8 ?? 00 00 00 ff 74 24 10 ff 74 24 10 ff 74 24 10 ff 74 24 10 ff d0 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {68 84 9b 50 f2 e8 ?? fe ff ff 50 e8 ?? fe ff ff ff 74 24 08 ff 74 24 08 ff d0 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 c2 03 32 10 40 80 38 00 0f}  //weight: 1, accuracy: High
        $x_1_5 = {64 a1 30 00 00 00 0f ?? ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

