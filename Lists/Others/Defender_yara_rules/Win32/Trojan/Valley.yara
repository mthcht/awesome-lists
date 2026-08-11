rule Trojan_Win32_Valley_MK_2147974738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valley.MK!MTB"
        threat_id = "2147974738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {c1 f0 9e 81 d9 ad d1 a3 9b c1 c9 02 c1 f2 a2 66 c1 b4 04 00 00 00 80 0b 66 81 c2 18 3a f7 d1 8d 8c 11 db 8f 8c ba 33 d9 66 c1 84 04 01 00 00 80 26 03 e9 c1 f8 ad}  //weight: 15, accuracy: High
        $x_10_2 = "\\\\.\\Warsaw_PM" wide //weight: 10
        $x_5_3 = "cmd.exe /c start \"\" /B cmd /C %s" wide //weight: 5
        $x_3_4 = "taskkill /f /im cmd.exe" wide //weight: 3
        $x_2_5 = "1EBE7ED7C9372896C3C28E541588DD12A08B24BA6BC3CEB699FCA838443886C6" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Valley_MKA_2147975240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valley.MKA!MTB"
        threat_id = "2147975240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {58 33 cb c0 f8 e1 2b ca d1 c1 f6 d2 98 c1 fa 29 0f c9 40 4a f7 d0 c1 c1 03}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Valley_MKB_2147975888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valley.MKB!MTB"
        threat_id = "2147975888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {8b 8c 4d 46 c6 04 a4 0f b3 d2 81 d5 03 00 00 00 8b c2 66 c1 c2 47 5a 33 cb 49 66 ff c0 2b d0 66}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Valley_MKC_2147975891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valley.MKC!MTB"
        threat_id = "2147975891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8d 0c 55 31 29 bc 9c 0f ab ca d3 c8 f6 da 66 81 d2 17 c9 f7 d8 86 d1 33 d8 0f ba f2 3e}  //weight: 20, accuracy: High
        $x_15_2 = {66 ff c2 03 e8 f7 da c0 ca 02 66 8b 84 16 d1 90 ff bf 66 f7 d9 66 ff ca 66 0f a3 d2 66 8b 8c 32 d4 90 ff bf}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

