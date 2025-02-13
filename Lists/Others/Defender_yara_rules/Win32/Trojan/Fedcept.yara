rule Trojan_Win32_Fedcept_A_2147647544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fedcept.A"
        threat_id = "2147647544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fedcept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 3e 34 6d 66 98 66 89 02 41 8a 01 42 42}  //weight: 1, accuracy: High
        $x_1_2 = {2b f0 32 ca 88 0c 06 40 8a 08 84 c9}  //weight: 1, accuracy: High
        $x_1_3 = {46 00 52 00 65 00 64 00 [0-6] 25 00 73 00 3f 00 55 00 49 00 44 00 3d 00 25 00 73 00 26 00 57 00 49 00 4e 00 56 00 45 00 52 00 3d 00 25 00 78 00 25 00 30 00 32 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fedcept_B_2147647591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fedcept.B"
        threat_id = "2147647591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fedcept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 7e 3c 81 3f 72 63 31 31 74}  //weight: 2, accuracy: High
        $x_1_2 = {25 00 73 00 3f 00 55 00 49 00 44 00 3d 00 25 00 73 00 26 00 57 00 49 00 4e 00 56 00 45 00 52 00 3d 00 25 00 78 00 25 00 30 00 32 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 64 00 6f 00 64 00 65 00 6c 00 65 00 74 00 65 00 00 00 2f 00 64 00 6f 00 66 00 69 00 6e 00 69 00 73 00 68 00 00 00 2f 00 64 00 6f 00 73 00 74 00 61 00 72 00 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "\" goto self_del_l64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fedcept_C_2147648115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fedcept.C"
        threat_id = "2147648115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fedcept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "STANDART_CODEC_NAG" ascii //weight: 1
        $x_1_2 = "videocodecsuite.net/thankyou.html" ascii //weight: 1
        $x_1_3 = {46 52 45 44 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_4 = "D:\\Work\\SpyWarePrj\\DeskTop\\CommonUnits\\IDhttp.pas" ascii //weight: 1
        $x_1_5 = {63 3a 5c 64 62 67 5f 61 6c 6c 6f 77 5f 64 65 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 6e 61 6c 79 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 73 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: Low
        $x_1_7 = "<fred_lib_file32 name=\"FRed32.dll\" />" ascii //weight: 1
        $x_1_8 = "It is not just a random bunch of stuff thrown together." ascii //weight: 1
        $x_1_9 = {49 00 4e 00 46 00 45 00 43 00 54 00 45 00 44 00 5f 00 50 00 08 00 4d 00 41 00 4c 00 46 00 4f 00 55 00 4e 00 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

