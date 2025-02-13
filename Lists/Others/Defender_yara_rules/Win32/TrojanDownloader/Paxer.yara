rule TrojanDownloader_Win32_Paxer_A_2147696564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Paxer.A"
        threat_id = "2147696564"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Paxer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IF exist \"%s\" GOTO AAA" ascii //weight: 1
        $x_1_2 = "IF exist \"%s\" GOTO BBB" ascii //weight: 1
        $x_1_3 = "content.dat" ascii //weight: 1
        $x_1_4 = {66 6c 61 73 68 70 6c 61 79 65 72 5f [0-16] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "%s\\deleteme.bat" ascii //weight: 1
        $x_1_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 68 61 72 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

