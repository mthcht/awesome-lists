rule Trojan_Win32_Bluether_A_2147693079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bluether.A!dha"
        threat_id = "2147693079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bluether"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 1e 88 0f 8a 1e 03 d9 81 e3 ff 00 00 00 8a 4c 1c 18 8a 1c 28 32 d9 8b 8c 24 28 01 00 00 88 1c 28 40 3b c1}  //weight: 5, accuracy: High
        $x_2_2 = "Bluthmon.exe" wide //weight: 2
        $x_1_3 = "%02d-%02d-%02d" ascii //weight: 1
        $x_1_4 = "C:\\TEMP\\2890.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Bluether_B_2147693080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bluether.B!dha"
        threat_id = "2147693080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bluether"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 a8 b3 10 6b 4e 09 a1 dd 8e cc 51 49 5e 32 00 26 12 63 ed 03 47 56 a7}  //weight: 5, accuracy: High
        $x_3_2 = "%04X/%c%d.asp" ascii //weight: 3
        $x_2_3 = "run ok!" ascii //weight: 2
        $x_2_4 = "is not exist path!" ascii //weight: 2
        $x_2_5 = "tw.chatnook.com:80,443;twnic.crabdance.com:80,443;asus.strangled.net:80,443;" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

