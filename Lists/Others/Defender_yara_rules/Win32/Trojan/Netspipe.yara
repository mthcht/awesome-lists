rule Trojan_Win32_Netspipe_A_2147945393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netspipe.A!dha"
        threat_id = "2147945393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netspipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 09 48 8d 44 24 40 48 89 44 24 38 c7 44 24 30 f4 01 00 00 c7 44 24 28 00 20 00 00 c7 44 24 20 00 20 00 00 41 b9 01 00 00 00 45 33 c0 ba 03 00 00 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

