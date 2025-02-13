rule Trojan_Win32_Yoddos_A_2147637803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yoddos.A"
        threat_id = "2147637803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[RepairSSDT] IRP_MJ_CREATE" ascii //weight: 1
        $x_1_2 = "&KiServiceTable==%08X" ascii //weight: 1
        $x_1_3 = {5c 64 72 69 76 65 72 73 5c 50 43 49 44 75 6d 70 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "RSDSv" ascii //weight: 1
        $x_1_5 = "#%d<<<<<I@C<<<<<%s!" ascii //weight: 1
        $x_1_6 = {6b 6d 6f 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yoddos_B_2147655130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yoddos.B"
        threat_id = "2147655130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 45 50 72 6f 74 4e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 45 50 72 6f 74 41 63 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 4f 46 54 57 41 52 45 5c 33 36 30 53 61 66 65 5c 73 61 66 65 6d 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 3f 00 0f 00 89 4c 24 28 66 8b 0d ?? ?? ?? ?? 89 54 24 2c 8a 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 68 02 00 00 80 66 89 4c 24 40 88 54 24 42 c7 44 24 28 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 54 24 10 8b 35 ?? ?? ?? ?? 8d 4c 24 14 6a 04 51 6a 04 50 68 ?? ?? ?? ?? 52 ff d6 8b 4c 24 10 8d 44 24 14 6a 04 50 6a 04 6a 00 68 ?? ?? ?? ?? 51 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Yoddos_C_2147661079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yoddos.C"
        threat_id = "2147661079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "#%d<<<<<I@C<<<<<%s!" ascii //weight: 10
        $x_1_2 = "SynFlood" ascii //weight: 1
        $x_1_3 = "ICMPFlood" ascii //weight: 1
        $x_1_4 = "UDPFlood" ascii //weight: 1
        $x_1_5 = "UDPSmallFlood" ascii //weight: 1
        $x_1_6 = "TCPFlood" ascii //weight: 1
        $x_1_7 = "MultiTCPFlood" ascii //weight: 1
        $x_1_8 = "DNSFlood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Yoddos_D_2147684136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yoddos.D"
        threat_id = "2147684136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4d 75 6c 74 69 54 43 50 46 6c 6f 6f 64 00}  //weight: 2, accuracy: High
        $x_1_2 = "Googlebot/2.1;" ascii //weight: 1
        $x_2_3 = {b9 01 00 00 00 85 c9 74 57 83 3d ?? ?? ?? ?? 01 75 02 eb 4c b8 63 00 00 00 90 b8 9d ff ff ff 90 6a 06 6a 01 6a 02 ff 15 ?? ?? ?? ?? 89 85 7c fd ff ff 6a 10 8d 55 f0 52 8b 85 7c fd ff ff 50 ff 15 ?? ?? ?? ?? b8 63 00 00 00 90 b8 9d ff ff ff 90 8b 8d 7c fd ff ff 51 ff 15 ?? ?? ?? ?? eb a0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

