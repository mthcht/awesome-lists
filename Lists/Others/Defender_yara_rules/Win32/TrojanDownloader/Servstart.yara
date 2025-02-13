rule TrojanDownloader_Win32_Servstart_A_2147711795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Servstart.A!bit"
        threat_id = "2147711795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Servstart"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zifuchuanduli" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Cacrk\\" ascii //weight: 1
        $x_1_3 = {57 ff d6 8b 45 ?? 03 c3 59 8a 08 80 c1 7a 80 f1 59 43 3b 5d ?? 88 08 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Servstart_B_2147712470_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Servstart.B!bit"
        threat_id = "2147712470"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Servstart"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 c0 56 c6 45 c1 49 c6 45 c2 44 c6 45 c3 3a c6 45 c4 32 c6 45 c5 30 c6 45 c6 31 c6 45 c7 34 c6 45 c8 2d c6 45 c9 53 c6 45 ca 56 c6 45 cb 38}  //weight: 1, accuracy: High
        $x_1_2 = {3b c6 7c e3 19 00 8b ?? ?? 8a 14 08 80 c2 7a 88 14 08 8b ?? ?? 8a 14 08 80 f2 ?? 88 14 08 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Servstart_C_2147714338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Servstart.C!bit"
        threat_id = "2147714338"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Servstart"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 0c 6d c6 44 24 0d 79 c6 44 24 0e 73 c6 44 24 0f 71 88 4c 24 11 c6 44 24 12 2e 88 4c 24 13 c6 44 24 16 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f1 53 c6 45 f2 53 c6 45 f3 53 c6 45 f4 53 c6 45 f5 53 c6 45 f6 56 c6 45 f7 49 c6 45 f8 44}  //weight: 1, accuracy: High
        $x_1_3 = "http://hackbox.f3322.org:808/Consys21.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

