rule TrojanDownloader_Win32_Urfisel_B_2147629929_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Urfisel.B"
        threat_id = "2147629929"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Urfisel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 e2 c1 ea 18 02 d0 8d 35}  //weight: 1, accuracy: High
        $x_1_2 = {ac 2a c2 32 c2 aa e2 f8}  //weight: 1, accuracy: High
        $x_1_3 = {51 57 53 ff 15 ?? ?? ?? ?? 85 c0 75 04 c9 c2 10 00 89 06 83 c6 04 33 c0 33 c9 49 f2 ae 59 e2 e0}  //weight: 1, accuracy: Low
        $x_1_4 = {74 32 66 81 fb 4d 5a 75 c3 33 c0 68}  //weight: 1, accuracy: High
        $x_1_5 = {81 3e 68 74 74 70 75 03 8d 76 07 81 3e 77 77 77 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

