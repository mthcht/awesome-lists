rule Trojan_Win32_GMack_A_2147723180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GMack.A!bit"
        threat_id = "2147723180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GMack"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 75 70 72 6f 63 68 65 61 74 2e 6e 65 74 2f [0-47] 42 75 67 54 72 61 70 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "PointBlank.exe" ascii //weight: 1
        $x_1_3 = "BugTrap.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

