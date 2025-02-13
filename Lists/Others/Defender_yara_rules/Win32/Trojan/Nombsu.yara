rule Trojan_Win32_Nombsu_A_2147627533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nombsu.A"
        threat_id = "2147627533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nombsu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 2e 74 78 74 00 00 00 2a 2e 78 6c 73 00 00 00 2a 2e 70 70 74 00 00 00 2a 2e 64 6f 63}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\lsass.exe\" u -ap -hp%s -r -tk \"%s\\plugin.dll" ascii //weight: 1
        $x_1_3 = "xcopy.exe /s /a /y /d:%s %s\\%s \"%s" ascii //weight: 1
        $x_1_4 = {8b ca 4f c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 ff 15 ?? ?? ?? 00 83 c4 10 83 f8 ff 5f 75 20 6a 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 75 02 5e c3 6a 06 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 68 04 01 00 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8d 44 24 08 50 6a 00 6a 00 68 ?? ?? ?? 00 6a 00 6a 00 ff 15 ?? ?? ?? 00 83 c4 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

