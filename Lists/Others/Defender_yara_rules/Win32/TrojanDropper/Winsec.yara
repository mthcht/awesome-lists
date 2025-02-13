rule TrojanDropper_Win32_Winsec_A_2147707751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Winsec.A!dha"
        threat_id = "2147707751"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Winsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 24 8a 4c 24 ?? 33 d2 0f be b9 [0-16] 4c 24 ?? 0f be 09 33 f9}  //weight: 1, accuracy: Low
        $x_2_2 = {3a 45 0a 64 65 6c 20 2f 61 20 64 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_1_3 = "%s is an essential element in Windows System configuration and management. %" ascii //weight: 1
        $x_1_4 = "%s /c netsh advfirewall firewall add rule name=\"%s\" dir=in action=allow service=\"%s\" enable=yes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

