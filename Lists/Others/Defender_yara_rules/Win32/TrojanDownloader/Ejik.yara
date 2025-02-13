rule TrojanDownloader_Win32_Ejik_F_2147607761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ejik.F"
        threat_id = "2147607761"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ejik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5b 8b e5 5d c3 00 00 00 ff ff ff ff 0a 00 00 00 5b 73 65 74 74 69 6e 67 73 5d 00 00 ff ff ff ff ?? 00 00 00 75 73 65 72 6e 61 6d 65 3d [0-16] ff ff ff ff 03 00 00 00 69 64 3d 00 ff ff ff ff 0a 00 00 00 76 65 72 3d 30 ?? ?? ?? ?? ?? 00 00 ff ff ff ff 04 00 00 00 72 6e 64 3d 00 00 00 00 ff ff ff ff 11 00 00 00 77 69 6e 64 6f 77 6e 65 77 73 75 70 73 2e 69 6e 69 00 00 00}  //weight: 100, accuracy: Low
        $x_5_2 = {41 41 41 00 45 58 45 46 49 4c 45 00 ff ff ff ff 10 00 00 00 52 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {45 58 45 46 49 4c 45 00 ff ff ff ff 10 00 00 00 52 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 0c 00 ff ff ff ff 03 00 00 00 ?? (61|2d|7a|30|2d|39) (61|2d|7a|30|2d|39) 00}  //weight: 5, accuracy: Low
        $x_5_4 = {31 00 00 00 45 58 45 46 49 4c 45 00 ff ff ff ff 08 00 00 00 35 35 34 34 2e 65 78 65}  //weight: 5, accuracy: High
        $x_1_5 = {70 61 73 73 77 6f 72 64 [0-80] 75 73 65 72 6e 61 6d 65 [0-80] 50 61 73 73 77 6f 72 64 [0-80] 55 73 65 72 6e 61 6d 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Ejik_G_2147607893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ejik.G"
        threat_id = "2147607893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ejik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 61 73 73 77 6f 72 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 75 73 65 72 6e 61 6d 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 50 61 73 73 77 6f 72 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 55 73 65 72 6e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_2 = "EIdAlreadyRegisteredAuthenticationMethod" ascii //weight: 1
        $x_1_3 = "recvfrom" ascii //weight: 1
        $x_1_4 = "getsockname" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_6 = "realm" ascii //weight: 1
        $x_1_7 = "EXEFILE" ascii //weight: 1
        $x_1_8 = "Regsvr32.exe /s " ascii //weight: 1
        $x_1_9 = "[settings]" ascii //weight: 1
        $x_1_10 = "username=" ascii //weight: 1
        $x_1_11 = "ver=" ascii //weight: 1
        $x_1_12 = "windownewsups.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

