rule Trojan_Win32_Mitav_A_2147684578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mitav.A"
        threat_id = "2147684578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mitav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/info.php?idd=" ascii //weight: 1
        $x_1_2 = {2d 72 20 22 25 31 22 20 25 2a [0-2] 45 4c 45 56 41 54 45 43 52 45 41 54 45 50 52 4f 43 45 53 53 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

