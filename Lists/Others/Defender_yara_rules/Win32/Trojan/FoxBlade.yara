rule Trojan_Win32_FoxBlade_C_2147814011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FoxBlade.C!dha"
        threat_id = "2147814011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FoxBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 2d 00 61 00 20 00 22 00 ?? ?? 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Wizard.dll" ascii //weight: 1
        $x_1_3 = {8d 4e fc 8b 01 33 c2 8b 11 4f 89 06 8d 31 85 ff 7f ee 8b 13 81 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

