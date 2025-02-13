rule TrojanDownloader_Win32_Delflob_F_2147599983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delflob.F"
        threat_id = "2147599983"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delflob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 ac ac a8 e2 f7 f7 b5 a1 b5 bd ac b9 ae b1 bc ab f6 bb b7 b5 f7 bc aa ae eb ea f6 bc b9 ac b9}  //weight: 1, accuracy: High
        $x_1_2 = "/drv32.data" ascii //weight: 1
        $x_1_3 = {63 3a 5c 74 6d 70 2e 62 61 74 00 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_5_4 = {8d 4d ac b2 d8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ac 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 b0 ba 06 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

