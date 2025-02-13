rule Trojan_Win32_Badobon_A_2147712428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Badobon.A"
        threat_id = "2147712428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Badobon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "a2guard.exe" ascii //weight: 1
        $x_1_2 = "pctsGui.exe" ascii //weight: 1
        $x_1_3 = "Norman_Malware_Cleaner.exe" ascii //weight: 1
        $x_1_4 = "FirewallGUI.exe" ascii //weight: 1
        $x_5_5 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 [0-16] 42 41 53 53 5f}  //weight: 5, accuracy: Low
        $x_5_6 = {41 64 6f 62 65 [0-16] 46 6c 61 73 68 [0-16] 54 65 6d 70 [0-16] 49 6e 69 74 [0-16] 4c 6f 67 6f 6e [0-16] 55 70 64 61 74 65 [0-16] 49 44 4d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

