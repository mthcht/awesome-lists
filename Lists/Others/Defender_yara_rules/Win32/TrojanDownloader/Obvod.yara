rule TrojanDownloader_Win32_Obvod_A_2147610911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obvod.A"
        threat_id = "2147610911"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obvod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetReadFile" ascii //weight: 10
        $x_10_2 = "WriteProcessMemory" ascii //weight: 10
        $x_10_3 = "CreateRemoteThread" ascii //weight: 10
        $x_10_4 = "<IFRAME FRAMEBORDER=0" ascii //weight: 10
        $x_10_5 = "<script language=\"javascript\" src=\"%s\"></script>" ascii //weight: 10
        $x_1_6 = "91.142.67.51" ascii //weight: 1
        $x_1_7 = "194.126.193.161" ascii //weight: 1
        $x_1_8 = "209.167.111.110" ascii //weight: 1
        $x_1_9 = "http://%s/rjsa/select.php?a=%s&b=%d&c=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Obvod_C_2147616234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obvod.C"
        threat_id = "2147616234"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obvod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 08 83 c8 ff 5e 83 c4 10 c3 8a 54 24 04 a0 ?? ?? ?? ?? 3a d0 75 18 8a 44 24 05 8a 0d ?? ?? ?? ?? 3a c1}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 54 24 18 88 14 07 8a 1c 01 03 da 81 e3 ff 00 00 00 8a 14 03 8a 1c 2e 32 da 8b 54 24 1c 88 1c 2e 46 3b f2 7c b4}  //weight: 2, accuracy: High
        $x_3_3 = {3b c1 75 71 80 3f 4f 75 6c 80 7f 01 4b 75 66 80 7f 02 20 75 60 6a}  //weight: 3, accuracy: High
        $x_1_4 = {5c 2a 61 64 2a 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = ".php?a=%s&b=%d&c=%d&d=%d&e=%d&f=%d&g=%d" ascii //weight: 1
        $x_1_6 = "SCROLLING=NO WIDTH=\"%d\" HEIGHT=\"%d\" SRC=\"%s\"></IFRAME>" ascii //weight: 1
        $x_1_7 = "<script src=\"%s\"></script>" ascii //weight: 1
        $x_1_8 = "ping.php/%d/%d" ascii //weight: 1
        $x_1_9 = "rjsa/select.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Obvod_D_2147616236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obvod.D"
        threat_id = "2147616236"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obvod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rjsa/select.php" ascii //weight: 10
        $x_6_2 = "Feed_Next fptr " ascii //weight: 6
        $x_4_3 = "216.95.196.22" ascii //weight: 4
        $x_4_4 = "209.167.111.110" ascii //weight: 4
        $x_2_5 = "Software\\Microsoft\\Internet Explorer\\New Windows" ascii //weight: 2
        $x_2_6 = "99C6D1BB-7555-474C-91DA-D8FB62A9CC75" ascii //weight: 2
        $x_2_7 = "00476C87-A276-49BF-86BC-FF005732430B" ascii //weight: 2
        $x_2_8 = "\\*ad*txt" ascii //weight: 2
        $x_2_9 = "Thread_FakeCheck()" ascii //weight: 2
        $x_1_10 = "<script src=\"%s\"></script>" ascii //weight: 1
        $x_1_11 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Obvod_H_2147645986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obvod.H"
        threat_id = "2147645986"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obvod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 2f 66 2e 70 68 70 3f 61 3d 25 73 26 62 3d 25 64 26 63 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 6f 70 75 70 6d 67 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {88 8e 00 01 00 00 88 8e 01 01 00 00 33 ff 8b c1 33 db 99 f7 7c 24 1c 8a 1c 31 8a 04 2a 03 c3 03 c7 25 ff 00 00 00 41 8b f8 81 f9 00 01 00 00 8a 14 37 88 54 31 ff 88 1c 37 7c d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Obvod_K_2147655473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obvod.K"
        threat_id = "2147655473"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obvod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/0xabad1dea.php?a=%s&b=%d&c=%d" ascii //weight: 1
        $x_1_2 = {70 6f 70 75 70 6d 67 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {88 8e 00 01 00 00 88 8e 01 01 00 00 33 ff 8b c1 33 db 99 f7 7c 24 1c 8a 1c 31 8a 04 2a 03 c3 03 c7 25 ff 00 00 00 41 8b f8 81 f9 00 01 00 00 8a 14 37 88 54 31 ff 88 1c 37 7c d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Obvod_M_2147679214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obvod.M"
        threat_id = "2147679214"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obvod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 fe 8a 44 0c ?? 8a 94 14 ?? ?? ?? ?? 32 c2 88 44 0c ?? 41 83 f9 20 7c e4}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 2a 61 64 2a 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 6f 70 75 70 6d 67 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 70 68 70 3f 61 3d 25 73 26 62 3d 25 64 26 63 3d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

