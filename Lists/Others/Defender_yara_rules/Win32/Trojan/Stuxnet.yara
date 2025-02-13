rule Trojan_Win32_Stuxnet_A_2147635799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stuxnet.A"
        threat_id = "2147635799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 37 6f 74 62 78 73 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 74 24 08 80 7e ?? 00 75 05 8d 46 ?? 5e c3 0f b7 46 ?? 57 50 8d 7e ?? 57 e8 ?? ?? ?? ?? 80 66 ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 28 ff 75 24 ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 51 38 5d c2 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stuxnet_B_2147636154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stuxnet.B"
        threat_id = "2147636154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 07 b8 ?? ?? ?? ?? eb ?? ff d0 8a 96 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 f4 4d 5a 90 00 c7 45 ec 0b ad fe ed}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 fc 50 e8 ?? ?? 00 00 50 ff d6 85 c0 7d 07 b8 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stuxnet_E_2147641118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stuxnet.E"
        threat_id = "2147641118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b2 00 eb 14 b2 01 eb 10 b2 02 eb 0c b2 03 eb 08 b2 04 eb 04 b2 05 eb 00 52 e8 04 00 00 00 ?? ?? ?? ?? 5a ff 22 e8 13 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5a 84 d2 74 25 fe ca 0f 84 82 00 00 00 fe ca 0f 84 bb 00 00 00 fe ca 0f 84 fe 00 00 00 fe ca 0f 84 40 01 00 00}  //weight: 1, accuracy: High
        $n_10_3 = {3d 02 06 24 ae 74 07 33 c0 e9}  //weight: -10, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Stuxnet_F_2147644014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stuxnet.F"
        threat_id = "2147644014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "s7otbxsx.dll" ascii //weight: 1
        $x_1_2 = "s7_get_password" ascii //weight: 1
        $x_1_3 = "s7H_start_cpu" ascii //weight: 1
        $x_1_4 = {8b 74 24 08 80 7e ?? 00 75 05 8d 46 ?? 5e c3 0f b7 46 ?? 57 50 8d 7e ?? 57 e8 ?? ?? ?? ?? 80 66 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

