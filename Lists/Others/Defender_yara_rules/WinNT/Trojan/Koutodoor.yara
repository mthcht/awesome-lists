rule Trojan_WinNT_Koutodoor_A_2147615626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Koutodoor.A"
        threat_id = "2147615626"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce" wide //weight: 1
        $x_1_2 = "KeServiceDescriptorTable" wide //weight: 1
        $x_1_3 = "\\Device\\rkdoor" wide //weight: 1
        $x_1_4 = "\\DosDevices\\rkdoor" wide //weight: 1
        $x_1_5 = "etc\\hosts" wide //weight: 1
        $x_1_6 = "fastfat.sys" ascii //weight: 1
        $x_1_7 = "ntfs.sys" ascii //weight: 1
        $x_1_8 = "\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_9 = "Start Page" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Koutodoor_B_2147625825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Koutodoor.B"
        threat_id = "2147625825"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\rkdoor" wide //weight: 1
        $x_1_2 = {ff 75 fc 8d 85 fc fe ff ff 50 e8 55 8b ec 57 33 ff 39 7d 14 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Koutodoor_C_2147625922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Koutodoor.C"
        threat_id = "2147625922"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "yfsa" wide //weight: 1
        $x_1_2 = "XvpHd" wide //weight: 1
        $x_1_3 = "wLBv" wide //weight: 1
        $x_1_4 = {ff 75 0c ff 75 08 6a 20 68 40 56 01 00 e8 55 8b ec 56 57 33 ff 39 7d 14 0f 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Koutodoor_D_2147629053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Koutodoor.D"
        threat_id = "2147629053"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 72 00 6b 00 64 00 6f 00 6f 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 43 00 4c 00 53 00 49 00 44 00 5c 00 7b 00 38 00 37 00 31 00 43 00 35 00 33 00 38 00 30 00 2d 00 34 00 32 00 41 00 30 00 2d 00 31 00 30 00 36 00 39 00 2d 00 41 00 32 00 45 00 41 00 2d 00 30 00 38 00 30 00 30 00 32 00 42 00 33 00 30 00 33 00 30 00 39 00 44 00 7d 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 48 00 6f 00 6d 00 65 00 50 00 61 00 67 00 65 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 25 73 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Koutodoor_E_2147630004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Koutodoor.E"
        threat_id = "2147630004"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "etc\\hosts" wide //weight: 2
        $x_2_2 = "\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce" wide //weight: 2
        $x_1_3 = {56 56 56 6a 01 8d 45 f4 6a 0f 50 56 56 56 ff 75 fc ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_2_4 = {55 8b ec 51 50 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 58 8b 45 08 8b 4d fc 89 08 c9 c2 04 00}  //weight: 2, accuracy: High
        $x_1_5 = {99 f7 7d 0c 8b 45 08 32 ?? 02}  //weight: 1, accuracy: Low
        $x_1_6 = {99 f7 7d 0c 8a 45 ff 32 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

