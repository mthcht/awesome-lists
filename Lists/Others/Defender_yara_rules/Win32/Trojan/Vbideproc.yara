rule Trojan_Win32_Vbideproc_A_2147707370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbideproc.A"
        threat_id = "2147707370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbideproc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3a 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 52 00 65 00 6d 00 6f 00 74 00 65 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 5c 00 [0-16] 5c 00 [0-16] 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_1_2 = "StartHide" ascii //weight: 1
        $x_1_3 = "KeepProcRunningAndRegistry" ascii //weight: 1
        $x_1_4 = "\\svchost32.exe" wide //weight: 1
        $x_1_5 = "\\Winsystem.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

