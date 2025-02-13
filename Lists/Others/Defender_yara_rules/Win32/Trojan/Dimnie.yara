rule Trojan_Win32_Dimnie_B_2147691729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dimnie.B"
        threat_id = "2147691729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dimnie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 f0 49 6b 7a 5e c7 45 f4 7c 61 6d 6b c7 45 f8 7d 7d 46 6b 66 c7 45 fc 6f 7e}  //weight: 2, accuracy: High
        $x_1_2 = {80 74 05 f0 0e 40 83 f8 0e 7c f5 e8}  //weight: 1, accuracy: High
        $x_2_3 = {c7 45 f4 64 7b 7c 7a c7 45 f8 6b 69 7c 5f}  //weight: 2, accuracy: High
        $x_1_4 = {88 45 fc 80 74 05 f4 08 40 83 f8 08 7c f5 e8}  //weight: 1, accuracy: High
        $x_2_5 = {c7 45 ec 44 72 7a 67 c7 45 f0 55 7c 61 40 c7 45 f4 7a 7d 74 7f}  //weight: 2, accuracy: High
        $x_1_6 = {80 74 05 ec 13 40 83 f8 13 7c f5 e8}  //weight: 1, accuracy: High
        $x_1_7 = "_DMNBEG_1234" ascii //weight: 1
        $x_1_8 = "nvpn.pwXXX" ascii //weight: 1
        $x_1_9 = {0f b6 d1 c1 e2 18 89 10 8a d1 80 e2 80 83 c0 04 f6 da 1a d2 80 e2 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dimnie_C_2147696797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dimnie.C"
        threat_id = "2147696797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dimnie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 c7 e3 06 ad e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 c9 ac 4a e8}  //weight: 1, accuracy: High
        $x_1_3 = "_DMNBEG_1234" ascii //weight: 1
        $x_2_4 = {49 6b 7a 5e c7 45 ?? 7c 61 6d 6b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dimnie_E_2147716820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dimnie.E"
        threat_id = "2147716820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dimnie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {0f b6 d0 c1 e2 18 89 14 31 8a d0 80 e2 80 83 c1 04 f6 da 1a d2 80 e2 1b 02 c0 32 c2 83 f9 28 7c d9}  //weight: 8, accuracy: High
        $x_2_2 = {81 e1 ff 01 00 00 5f 3d cd ab cd ab 75 05 b8 48 00 00 00 0f}  //weight: 2, accuracy: High
        $x_2_3 = "babbabbab.ru" ascii //weight: 2
        $x_2_4 = "babfabbab.ua" ascii //weight: 2
        $x_2_5 = "babfabbab.pw" ascii //weight: 2
        $x_1_6 = "mentioned Million schoolwork" ascii //weight: 1
        $x_1_7 = "sysadmin Curly travel Lucas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dimnie_G_2147718516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dimnie.G"
        threat_id = "2147718516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dimnie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_DMNBEG_1234" ascii //weight: 2
        $x_2_2 = "_DMNEND_" ascii //weight: 2
        $x_1_3 = "seclist.site" ascii //weight: 1
        $x_1_4 = "ping -n 1 127.0.0.1 && " wide //weight: 1
        $x_1_5 = {c7 45 f4 61 65 69 6f 33 db 66 c7 45 f8 75 00 c7 45 dc 62 63 64 66 c7 45 e0 67 68 6a 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

