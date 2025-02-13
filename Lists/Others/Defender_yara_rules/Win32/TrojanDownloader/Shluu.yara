rule TrojanDownloader_Win32_Shluu_A_2147624240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Shluu.A"
        threat_id = "2147624240"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Shluu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 e2 10 0b d0 8b 44 24 14 0f af ca 0f af c8 0f af c8 33 d2 bf 19 00 00 00 8b c1 f7 f7 8b 74 24 20 83 cf ff 80 c2 61 88 16}  //weight: 2, accuracy: High
        $x_1_2 = {49 73 55 73 65 72 41 64 6d 69 6e 00 73 65 74 75 70 61 70 69 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {f6 04 24 09 74 0d 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

