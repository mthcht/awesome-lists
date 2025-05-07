rule Trojan_Win64_SystemBC_RPZ_2147839246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBC.RPZ!MTB"
        threat_id = "2147839246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c3 8a 94 2b c0 fb ff ff 02 c2 8a 8c 28 c0 fb ff ff 88 8c 2b c0 fb ff ff 88 94 28 c0 fb ff ff 02 ca 8a 8c 29 c0 fb ff ff 30 0e 48 ff c6 48 ff cf}  //weight: 1, accuracy: High
        $x_1_2 = "backconnect\\server.exe" ascii //weight: 1
        $x_1_3 = "_loader.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SystemBC_YAG_2147911541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBC.YAG!MTB"
        threat_id = "2147911541"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 18 63 6c 6f 73 c7 45 1c 65 73 6f 63 c7 45 20 6b 65 74 00 c7 45 b8 73 68 75 74 c7 45 bc 64 6f 77 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SystemBC_E_2147913408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBC.E"
        threat_id = "2147913408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 78 48 8b 90 30 01 00 00 48 8b 44 24 78 48 8b ?? 20 01 00 00 48 8b 44 24 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SystemBC_MKV_2147913413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBC.MKV!MTB"
        threat_id = "2147913413"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b cf 8a 04 1f 30 03 48 ff c3 48 83 e9 01 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b c6 4c 2b c0 48 8d 4d ?? 48 03 ca 48 ff c2 41 8a 04 08 34 36 88 01 48 3b d3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SystemBC_F_2147920294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBC.F"
        threat_id = "2147920294"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 20 48 c7 c1 20 bf 02 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 ec 20 48 c7 c1 02 00 00 00 48 8d 57 52 4c 8b c7 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SystemBC_SD_2147940856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBC.SD!MTB"
        threat_id = "2147940856"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c9 48 c1 e1 02 48 01 ca 33 45 30 89 02 83 45 e4 01 8b 45 e4 48 63 d0 48 8b 45 d8 48 c1 e8 02 48 39 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

