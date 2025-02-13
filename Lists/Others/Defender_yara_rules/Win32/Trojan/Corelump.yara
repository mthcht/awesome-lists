rule Trojan_Win32_Corelump_A_2147827202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Corelump.A!dha"
        threat_id = "2147827202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Corelump"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 ff 15 ?? ?? ?? ?? [0-3] 81 78 02 45 9e be bd}  //weight: 1, accuracy: Low
        $x_1_2 = {5d 5d 3e c5 85 c8 77 59 d5 e7 00 45 a3 11 57 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

