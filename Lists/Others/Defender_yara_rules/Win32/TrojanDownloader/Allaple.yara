rule TrojanDownloader_Win32_Allaple_A_2147602079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allaple.gen!A"
        threat_id = "2147602079"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allaple"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = ".state.co.us/consline/complaint.pdf" ascii //weight: 5
        $x_5_2 = "www.pks-jakarta.or.id/pics/default" ascii //weight: 5
        $x_1_3 = "email_downloader" ascii //weight: 1
        $x_10_4 = {6a ff 6a 00 e8 ?? ?? ?? ff 8b d8 85 db 74 0c e8 ?? ?? ?? ff 3d b7 00 00 00 75 0d 53 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Allaple_B_2147602080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allaple.gen!B"
        threat_id = "2147602080"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allaple"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "FastMM Borland" ascii //weight: 10
        $x_10_2 = {6a ff 6a 00 e8 ?? ?? ?? ff 8b d8 85 db 74 0c e8 ?? ?? ?? ff 3d b7 00 00 00 75 0d 53 e8}  //weight: 10, accuracy: Low
        $x_1_3 = "pics/default/irs_" ascii //weight: 1
        $x_1_4 = "email_downloader" ascii //weight: 1
        $x_1_5 = "Windows NT 5.1; en;) Gecko/" ascii //weight: 1
        $x_3_6 = {69 72 73 5f 65 66 69 6c 6c 2e 70 68 70 00 55 8b}  //weight: 3, accuracy: High
        $x_3_7 = {53 79 73 74 65 6d 52 6f 6f 74 00 00 65 78 70 6c 6f 72 65 72 20 68 74 74 70 3a 2f 2f [0-48] 2e 70 64 66}  //weight: 3, accuracy: Low
        $x_3_8 = {2e 70 64 66 00 00 ff ff ff ff 0c 00 00 00 5c 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Allaple_C_2147605366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allaple.gen!C"
        threat_id = "2147605366"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allaple"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://akawin.com" ascii //weight: 1
        $x_1_2 = "http://fx-date.com" ascii //weight: 1
        $x_1_3 = "http://team-america.100webspace.net/gl.php?id=1" ascii //weight: 1
        $x_3_4 = {69 6e 73 74 61 6c 6c 2e 65 78 65 00 ff ff ff ff 09 00 00 00 63 73 72 73 73 2e 65 78 65 00 00 00 ff ff ff ff 0d 00 00 00 74 6d 70 64 6f 77 6e 33 33 2e 64 6c 6c}  //weight: 3, accuracy: High
        $x_3_5 = {68 74 74 70 3a 2f 2f 61 67 2e 63 61 2e 67 6f 76 2f 63 6d 73 5f 70 64 66 73 2f 70 72 65 73 73 2f 4e 31 34 37 38 5f 43 6f 6d 70 6c 61 69 6e 74 41 54 26 54 55 6e 61 75 74 68 6f 72 69 7a 65 64 43 68 61 72 67 65 73 46 49 4e 41 4c 5f 54 42 46 32 2e 70 64 66 00 00 00 00 ff ff ff ff 11 00 00 00 63 3a 5c 46 49 4e 41 4c 5f 54 42 46 32 2e 70 64 66}  //weight: 3, accuracy: High
        $x_2_6 = {63 6f 6f 6b 69 65 73 2e 74 78 74 00 ff ff ff ff 17 00 00 00 6d 79 73 71 6c 34 2d 76 68 2e 61 6d 65 6e 77 6f 72 6c 64 2e 63 6f 6d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Allaple_D_2147605550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Allaple.gen!D"
        threat_id = "2147605550"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Allaple"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 a4 a9 40 00 e8 ?? ?? ff ff b8 a8 a9 40 00 e8 ?? ?? ff ff b8 ac a9 40 00 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 40 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "/irs_efill.php" ascii //weight: 1
        $x_1_3 = {74 6d 70 64 6f 77 6e 33 ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

