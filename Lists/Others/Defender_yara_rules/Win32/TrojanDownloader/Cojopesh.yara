rule TrojanDownloader_Win32_Cojopesh_B_2147630219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cojopesh.B"
        threat_id = "2147630219"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cojopesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 4d 0f 85 ?? 01 00 00 0f be 8d d8 ea ff ff 83 f9 5a 0f 85 ?? 01 00 00 83 7d 0c 00 0f 85 ?? 01 00 00 c6 85 ?? ?? ff ff 00 b9 40 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa c7 85 ?? ?? ff ff 44 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {eb aa 8b 45 fc 8a 08 88 8d ?? ?? ff ff 8b 55 fc 8a 42 01 88 85 ?? ?? ff ff 83 7d 0c 00 75 34}  //weight: 1, accuracy: Low
        $x_1_3 = {68 10 27 00 00 ff 15 ?? ?? 40 00 83 3d ?? ?? 40 00 00 74 13 68 80 8d 5b 00 ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 eb 8a 68 00 e0 2e 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "ASMDJHG176ERTDUYTQUWYETDUYT1827368E891E2YI" ascii //weight: 1
        $x_1_5 = "98798123876" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

