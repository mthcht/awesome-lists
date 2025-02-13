rule Trojan_Win32_Cadlotcorg_A_2147718877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cadlotcorg.A!dha"
        threat_id = "2147718877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadlotcorg"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 35 64 09 42 00 b8 af a9 6e 5e f7 e6 8b ce c1 ea 07 69 c2 5b 01 00 00 2b c8 74 1e b8 59 21 37 6c}  //weight: 1, accuracy: High
        $x_1_2 = {58 3a 5c 00 80 c3 41 50 88 5c 24 ?? ff 15 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\ProgramData\\Log.txt" ascii //weight: 1
        $x_1_4 = {58 3a 5c 00 58 3a 5c 00 53 79 73 74 65 6d 44 72 69 76 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cadlotcorg_B_2147719192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cadlotcorg.B!dha"
        threat_id = "2147719192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadlotcorg"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/destroyos" wide //weight: 1
        $x_1_2 = "/destroyusb" wide //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive" ascii //weight: 1
        $x_1_4 = "C:\\Program Files\\*" wide //weight: 1
        $x_1_5 = "C:\\Program Files\\Common Files\\System\\*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

