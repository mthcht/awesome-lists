rule Trojan_Win32_Garrurusty_A_2147645372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Garrurusty.A"
        threat_id = "2147645372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Garrurusty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 be 03 00 00 00 99 f7 fe 8a 04 29 80 c2 41 32 c2 88 04 29 41 3b cb 72 e6}  //weight: 10, accuracy: High
        $x_1_2 = "DrWatson.dll" wide //weight: 1
        $x_1_3 = "DrWatson.cfg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Garrurusty_A_2147645372_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Garrurusty.A"
        threat_id = "2147645372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Garrurusty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c ff 2a 04 29 88 04 3a 8d 04 1a 99 f7 fe 41 3b ce 7c ed}  //weight: 1, accuracy: High
        $x_1_2 = "pipe\\NannedPipe" wide //weight: 1
        $x_1_3 = {68 20 bf 02 00 ff d7 83 fe 08 74 27 83 fe 05 74 22 83 fe 06 74 1d 83 fe 07 74 18 83 fe 04 75 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Garrurusty_A_2147645372_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Garrurusty.A"
        threat_id = "2147645372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Garrurusty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be c3 83 e8 49 89 55 f8 0f 84 a6 00 00 00 83 e8 09 0f 84 9d 00 00 00 48 0f 85 16 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f 84 6f 02 00 00 66 3b ce 75 0c 66 39 70 02 75 06 66 39 78 06 74 15}  //weight: 1, accuracy: High
        $x_1_3 = {70 00 6c 00 75 00 74 00 6f 00 6e 00 69 00 75 00 6d 00 00 00 65 00 78 00 69 00 73 00 74 00 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "dcoms.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Garrurusty_A_2147645372_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Garrurusty.A"
        threat_id = "2147645372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Garrurusty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0c ff 2a 04 29 88 04 3a 8d 04 1a 99 f7 fe 41 3b ce 7c ed}  //weight: 10, accuracy: High
        $x_10_2 = {3d 99 00 00 00 0f 84 f2 fa ff ff 3d 9a 00 00 00 0f 84 e7 fa ff ff 3d 85 00 00 00 75 1e}  //weight: 10, accuracy: High
        $x_1_3 = "WebMoney Keeper Classic" wide //weight: 1
        $x_1_4 = "xiangyin.dyndns-web.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

