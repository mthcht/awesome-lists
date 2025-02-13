rule DoS_Win32_DesertBlade_C_2147814016_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/DesertBlade.C!dha"
        threat_id = "2147814016"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "DesertBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.wipe" ascii //weight: 1
        $x_1_2 = {e8 2b 57 fa ff 48 8b 44 24 20 48 8b 4c 24 28 48}  //weight: 1, accuracy: High
        $x_1_3 = {e8 a7 0a 00 00 48 8b 04 24 48 89 44 24 60 48 8b 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

