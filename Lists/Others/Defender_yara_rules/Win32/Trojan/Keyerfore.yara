rule Trojan_Win32_Keyerfore_A_2147709684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keyerfore.A!bit"
        threat_id = "2147709684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keyerfore"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "### Started logging at:" ascii //weight: 1
        $x_1_2 = "%appdata%\\svchost" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = {66 74 70 2e [0-16] 2e 63 6f 6d 00 55 53 45 52 20 [0-32] 0d 0a 00 50 41 53 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

