rule Trojan_Win32_Elkmil_2147602428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elkmil"
        threat_id = "2147602428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elkmil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 00 4f 00 54 00 4f 00 20 00 53 00 54 00 41 00 52 00 54 00 00 00 1a 00 00 00 5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: High
        $x_1_2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden]" wide //weight: 1
        $x_1_3 = "regedit.exe /s " wide //weight: 1
        $x_3_4 = {c7 45 fc 33 00 00 00 c7 85 58 ff ff ff ?? ?? ?? ?? c7 85 50 ff ff ff 08 00 00 00 8d 95 50 ff ff ff 8d 8d 60 ff ff ff ff 15 ?? ?? ?? ?? 6a 00 8d 8d 60 ff ff ff 51 ff 15}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

