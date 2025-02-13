rule Trojan_Win32_Razmeeg_A_2147683335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razmeeg.A"
        threat_id = "2147683335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razmeeg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 71 04 00 00 01 02 50 06 17 59 91 61 d2 81 04 00 00 01 06 17 59 0a 06 16 30 dd 2a 00}  //weight: 1, accuracy: High
        $x_1_2 = "/zemra/gate.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

