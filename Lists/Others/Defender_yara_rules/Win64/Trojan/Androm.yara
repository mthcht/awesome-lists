rule Trojan_Win64_Androm_GBS_2147834707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Androm.GBS!MTB"
        threat_id = "2147834707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 8d 0c 10 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 50 ff 41 0f b6 c8 41 2a c9 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 10 49 83 c0 02 4b 8d 04 02 48 3d 52 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Androm_RJ_2147837747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Androm.RJ!MTB"
        threat_id = "2147837747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 60 99 83 e2 03 03 c2 c1 f8 02 48 98 48 89 84 24 b0 00 00 00 8b 44 24 60 99 83 e2 03 03 c2 83 e0 03 2b c2 c1 e0 03 0f b6 c8 48 8b 84 24 b0 00 00 00 8b 44 84 20 d3 e8 25 ff 00 00 00 48 63 4c 24 60 48 8b 94 24 d0 00 00 00 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Androm_RG_2147895375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Androm.RG!MTB"
        threat_id = "2147895375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 24 38 48 8b 4c 24 20 0f be 09 33 c8 8b c1 48 8b 4c 24 20 88 01 48 8b 44 24 20 48 ff c0 48 89 44 24 20 eb c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Androm_CCHA_2147901149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Androm.CCHA!MTB"
        threat_id = "2147901149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 8a 6a 02 00 48 89 85 d0 00 00 00 48 8d 05 85 6a 02 00 48 89 85 d8 00 00 00 48 8d 05 7e 6a 02 00 48 89 85 e0 00 00 00 48 8d 05 84 6a 02 00 48 89 85 e8 00 00 00 48 8d 05 80 6a 02 00 48 89 85 f0 00 00 00 48 8d 05 81 6a 02 00 48 89 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Androm_AMX_2147925514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Androm.AMX!MTB"
        threat_id = "2147925514"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://176.111.174.140/api/xloader.bin" ascii //weight: 10
        $x_4_2 = "C:\\Documents and Settings\\JohnDo" ascii //weight: 4
        $x_2_3 = "ProcessHacker" ascii //weight: 2
        $x_2_4 = "x64dbg" ascii //weight: 2
        $x_2_5 = "procmon.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

