rule TrojanDownloader_Win32_Uoolop_A_2147708774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Uoolop.A!bit"
        threat_id = "2147708774"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Uoolop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 32 8b fe 34 ?? 83 c9 ff 2a c2 34 ?? 88 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Uoolop_B_2147709391_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Uoolop.B!bit"
        threat_id = "2147709391"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Uoolop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 32 8b fe 34 cb 83 c9 ff 2a c2 34 73 88 04 32}  //weight: 1, accuracy: High
        $x_1_2 = {8a c2 b1 03 2c 27 8b fe f6 e9 8a 0c 32 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

