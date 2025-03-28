rule Trojan_Win32_MadPebble_A_2147937187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MadPebble.A!dha"
        threat_id = "2147937187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MadPebble"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fsutil.exe file setzerodata offset" ascii //weight: 1
        $x_1_2 = {c7 45 e0 50 00 68 00 c7 45 e4 79 00 73 00 c7 45 e8 69 00 63 00 c7 45 ec 61 00 6c 00 c7 45 f0 44 00 72 00 c7 45 f4 69 00 76 00 c7 45 f8 65 00 25 00 c7 45 fc 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 e0 64 00 6c 00 c7 45 e4 6c 00 3b 00 c7 45 e8 2a 00 2e 00 c7 45 ec 65 00 78 00 c7 45 f0 65 00 3b 00 c7 45 f4 2a 00 2e 00 c7 45 f8 73 00 79 00 c7 45 fc 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

