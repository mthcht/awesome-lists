rule TrojanDownloader_Win32_Bizdup_2147606613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bizdup"
        threat_id = "2147606613"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bizdup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 00 00 00 50 6c 75 67 4c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {07 00 00 00 43 75 63 6b 6f 6f}  //weight: 1, accuracy: High
        $x_1_3 = {08 00 00 00 7e 75 70 73 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 6e 65 77 75 70 ?? 2e 74 78 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = "ThirdSoftInfo2" ascii //weight: 1
        $x_1_6 = "?SoftName=" ascii //weight: 1
        $x_1_7 = "SendSoftInfo2" ascii //weight: 1
        $x_1_8 = {d7 a2 b2 e1 b1 ed be af b8 e6 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Bizdup_B_2147617106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bizdup.gen!B"
        threat_id = "2147617106"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bizdup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 6e 65 77 75 70 ?? 2e 74 78 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {d7 a2 b2 e1 b1 ed be af b8 e6 00}  //weight: 1, accuracy: High
        $x_1_3 = "Protectedstorl" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\DataAccess" ascii //weight: 1
        $x_1_5 = {4d 53 44 4e 53 76 63 2e 64 6c 6c 00 4d 61 69 6e 74 65 6e 61 6e 63 65 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

