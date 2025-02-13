rule Trojan_Win32_Resmu_A_2147637440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Resmu.A!rootkit"
        threat_id = "2147637440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Resmu"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SystemRoot\\System32\\chktsk.txt" wide //weight: 1
        $x_1_2 = "\\SystemRoot\\System32\\svlogf.log" wide //weight: 1
        $x_1_3 = "GET /script.php?t=%u&a=" ascii //weight: 1
        $x_1_4 = {5c 73 72 65 6e 75 6d 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

