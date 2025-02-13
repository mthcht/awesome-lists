rule Trojan_Win32_Rirlged_B_2147602401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rirlged.gen!B"
        threat_id = "2147602401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rirlged"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 49 4e 4c 4f 47 4f 4e 00 00 00 00 59 6f 75 20 6c 6f 67 67 65 64 20 6f 6e 20 61 74 20 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 0a 00 54 68 65 20 68 61 73}  //weight: 1, accuracy: High
        $x_1_2 = "The debug privilege has been added to PasswordReminder." ascii //weight: 1
        $x_1_3 = {54 72 6f 6a 61 6e 53 5f 44 4c 4c (20|2e) 44 4c 4c}  //weight: 1, accuracy: Low
        $x_1_4 = "seven-eleven QQ:10531515 E-mail:cnwangming@163.com" ascii //weight: 1
        $x_1_5 = "!*_*->seven-eleven<-*_*!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Rirlged_A_2147610056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rirlged.gen!A"
        threat_id = "2147610056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rirlged"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3c 3e 90 90 90 a1 75 40 81 7c 3e 08 c3 90 90 90 75 36}  //weight: 2, accuracy: High
        $x_1_2 = {74 09 81 7d ?? 73 45 72 76 74 08}  //weight: 1, accuracy: Low
        $x_2_3 = {c3 dc c2 eb 3a 25 73 0a d3 f2 c3 fb 3a 25 73 0a}  //weight: 2, accuracy: High
        $x_1_4 = "!*_*->seven-eleven<-*_*!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

