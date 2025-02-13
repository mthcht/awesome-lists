rule TrojanDownloader_Win32_Tinub_A_2147691046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tinub.A"
        threat_id = "2147691046"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&cacls c:\\ /e /g everyone:f" wide //weight: 1
        $x_1_2 = "Open():.Write WritFso('m').GetChunk(StrLen):.SaveToFile" wide //weight: 1
        $x_1_3 = "admin password" wide //weight: 1
        $x_1_4 = {00 00 5c 00 70 00 69 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 2e 00 74 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 2e 00 72 00 61 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_2_7 = "Timnub" wide //weight: 2
        $x_2_8 = {00 00 4f 00 75 00 74 00 49 00 50 00 71 00 31 00 30 00 30 00 00 00}  //weight: 2, accuracy: High
        $x_2_9 = "PigK21" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Tinub_2147692892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tinub"
        threat_id = "2147692892"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 00 72 00 61 00 72 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "addnub" wide //weight: 2
        $x_3_3 = "http://122.228.228.7" wide //weight: 3
        $x_1_4 = "iswait" wide //weight: 1
        $x_1_5 = "isend" wide //weight: 1
        $x_1_6 = "isover" wide //weight: 1
        $x_1_7 = "isstop" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

