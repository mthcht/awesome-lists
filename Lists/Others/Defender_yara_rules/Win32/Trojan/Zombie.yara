rule Trojan_Win32_Zombie_NBJ_2147826899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zombie.NBJ!MTB"
        threat_id = "2147826899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zombie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c9 ff 8b f8 33 c0 f2 ae f7 d1 2b f9 8d 54 24 2c 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4}  //weight: 1, accuracy: High
        $x_1_2 = {ff 15 e8 30 40 00 25 07 00 00 80 79 05 48 83 c8 f8 40 05 2e 14 00 00 89 44 24 60 8d 4c 24 64}  //weight: 1, accuracy: High
        $x_1_3 = "/c del" ascii //weight: 1
        $x_1_4 = "COMSPEC" ascii //weight: 1
        $x_1_5 = "_.exe" ascii //weight: 1
        $x_1_6 = "\\Zombie.exe" ascii //weight: 1
        $x_1_7 = "WINNT" ascii //weight: 1
        $x_1_8 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zombie_RB_2147896803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zombie.RB!MTB"
        threat_id = "2147896803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zombie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 30 08 57 00 30 22 46 00 d0 f7 19 00 2a 5e 58 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

