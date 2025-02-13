rule Trojan_Win32_Reghack_A_2147623462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reghack.A"
        threat_id = "2147623462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reghack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6f 70 65 6e 00 73 65 6c 66 64 65 6c 00 2e 62 61 74 00 64 65 6c 20 00 0d 0a 00 72 6d 64 69 72 20 00 00 20 00 62 61 74 63 68 66 69 6c 65 2e 62 61 74}  //weight: 10, accuracy: High
        $x_10_2 = "REGEDIT.EXE /S \"%~f0\"" ascii //weight: 10
        $x_1_3 = "[-HKEY_CURRENT_USER\\Software]" ascii //weight: 1
        $x_1_4 = "[-HKEY_CURRENT_USER]" ascii //weight: 1
        $x_1_5 = "[-HKEY_CLASSES_ROOT]" ascii //weight: 1
        $x_1_6 = "[-HKEY_USERS\\.DEFAULT]" ascii //weight: 1
        $x_1_7 = "[HKEY_CURRENT_CONFIG\\SYSTEM]9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

