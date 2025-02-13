rule Trojan_Win32_Neconyd_A_2147682400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neconyd.A"
        threat_id = "2147682400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neconyd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "job^rev=%s^os=%s" wide //weight: 1
        $x_1_2 = "GRABFTPS" wide //weight: 1
        $x_1_3 = "^site=%s^searches=%s^clicks" wide //weight: 1
        $x_1_4 = {66 83 38 00 56 8b f1 8b c8 74 08 41 41 66 83 39 00 75 f8 0f b7 16 66 89 11 41 41 46 46 66 85 d2 75 f1 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neconyd_A_2147682400_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neconyd.A"
        threat_id = "2147682400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neconyd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 c8 55 0f 00 57 ff 15 28 80 40 00 57 8b f0 8d 45 f8 50 68 40 42 0f 00 56 53 ff 15 1c 80 40 00 80 3d 54 92 40 00 00 b9 54 92 40 00 8b c1 74 06 40 80 38 00 75 fa 2b c1 50 e8 f0 fd ff ff 8d 9e c8 ac 00 00 bf 60 ae 0a 00 a1 8c e8 41 00 40 be ff 00 00 00 23 c6 a3 8c e8 41 00 ff 15 20 80 40 00 a1 8c e8 41 00 0f b6 80 98 ec 41 00 03 05 84 e6 41 00 68 84 03 00 00 23 c6 a3 84 e6 41 00 e8 4a 01 00 00 85 c0 59 74 07 50 e8 62 00 00 00 59}  //weight: 1, accuracy: High
        $x_1_2 = "o0e[Eseof ]e jncpa eiowkEO" ascii //weight: 1
        $x_1_3 = "LOei ENuq" ascii //weight: 1
        $x_1_4 = "ioEoe NEd1uiw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

