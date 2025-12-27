rule Trojan_Win32_FatBeehive_C_2147957552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatBeehive.C!dha"
        threat_id = "2147957552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatBeehive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 f6 0f b6 c1 03 55 [0-1] 6b c0 55 32 02 88 04 0f 41 83 f9 20}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 0f ff 02 04 0f 34 [0-1] 88 04 0f 41 83 f9 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

