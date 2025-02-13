rule Trojan_Win32_Zipparch_E_2147680525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zipparch.E"
        threat_id = "2147680525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zipparch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Borland\\Delphi\\RTL" wide //weight: 2
        $x_2_2 = "sms_count" wide //weight: 2
        $x_2_3 = ".ru/" wide //weight: 2
        $x_1_4 = "?file_id=" wide //weight: 1
        $x_1_5 = "alt_pay" wide //weight: 1
        $x_1_6 = "obtain password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zipparch_F_2147680526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zipparch.F"
        threat_id = "2147680526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zipparch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SevenZipVCL" ascii //weight: 100
        $x_10_2 = "nfZW7LjVQqK73KxP" wide //weight: 10
        $x_10_3 = "RRR 9313266354" wide //weight: 10
        $x_10_4 = "Enter password from reply SMS." wide //weight: 10
        $x_2_5 = "abonent_price" wide //weight: 2
        $x_2_6 = "abonent_currency" wide //weight: 2
        $x_1_7 = {61 00 62 00 6f 00 6e 00 65 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 00 5f 00 70 00 72 00 69 00 63 00 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 00 5f 00 63 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zipparch_G_2147680527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zipparch.G"
        threat_id = "2147680527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zipparch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fsdf$sdf5_r" wide //weight: 1
        $x_1_2 = "pay.ru/robo-pay.php" wide //weight: 1
        $x_1_3 = "sms_pay" wide //weight: 1
        $x_1_4 = "SevenZipVCL" ascii //weight: 1
        $x_1_5 = "RRR 931326" wide //weight: 1
        $x_1_6 = {9a bd 64 51 39 1c 44 d5 9a 2c 25 5b 21 ba d1 78 f2 ed 58 3d 6f 4c 9a d9 0a e0 1e 00 fe c6 b5 5a}  //weight: 1, accuracy: High
        $x_1_7 = "abonent_price" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

