rule TrojanDownloader_Win32_Dabelor_A_2147617607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dabelor.A"
        threat_id = "2147617607"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabelor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 00 00 00 57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 00 00 53 83 c4 f8}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff ff 0a 00 00 00 6d 65 72 6d 61 6e 2e 65 78 65 00 00 ff ff ff ff 09 00 00 00 78 65 72 6f}  //weight: 1, accuracy: High
        $x_1_3 = {6c 00 00 00 ff ff ff ff 0b 00 00 00 6d 75 73 68 69 6d 75 2e 65 78 65 00 55 8b ec 33 c0 55 68 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

