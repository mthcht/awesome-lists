rule Trojan_Win32_MCCrash_MA_2147836792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MCCrash.MA!MTB"
        threat_id = "2147836792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MCCrash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 02 6a 02 6a 00 6a 02 68 00 00 00 40 8d 45 a0 8b 0d 84 46 40 00 8b 15 8c 46 40 00 e8 ?? ?? ?? ?? 8b 45 a0 e8 ?? ?? ?? ?? 50 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 13 85 d2 74 19 c7 03 00 00 00 00 8b 4a f8 49 7c 0d ff 4a f8 75 08 8d 42 f8 e8 63 fa ff ff 83 c3 04 4e 75 db}  //weight: 5, accuracy: High
        $x_1_3 = "LockResource" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

