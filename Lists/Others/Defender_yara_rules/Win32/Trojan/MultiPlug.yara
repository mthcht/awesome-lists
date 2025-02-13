rule Trojan_Win32_MultiPlug_DSK_2147741880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MultiPlug.DSK!MTB"
        threat_id = "2147741880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MultiPlug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {88 55 0b c0 65 0b 02 8a 45 0b 24 c0 0a c8 8a c2 c0 e0 06 80 e2 fc 88 45 0b 0a e8 8b 45 f0 c0 e2 04 0a d3 88 0c 06 88 54 06 01}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MultiPlug_PDSK_2147744428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MultiPlug.PDSK!MTB"
        threat_id = "2147744428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MultiPlug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ff 7f 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 ff d5 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MultiPlug_PVE_2147755544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MultiPlug.PVE!MTB"
        threat_id = "2147755544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MultiPlug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b7 59 e7 1f f7 a4 24 ?? ?? ?? ?? 8b 84 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 83 c4 04 85 f6 0f 8d 1f 00 81 ac 24 ?? ?? ?? ?? b3 30 c7 6b 81 84 24 ?? ?? ?? ?? 21 f4 7c 36 30 0c ?? 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MultiPlug_PVF_2147755790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MultiPlug.PVF!MTB"
        threat_id = "2147755790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MultiPlug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 b7 59 e7 1f f7 a4 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 81 84 24 ?? ?? ?? ?? f3 ae ac 68 81 ac 24 ?? ?? ?? ?? b3 30 c7 6b 81 84 24 ?? ?? ?? ?? 21 f4 7c 36 30 0c 1e 56 e8 ?? ?? ?? ?? 8b f0 83 c4 04 85 f6 0f 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MultiPlug_PVA_2147756452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MultiPlug.PVA!MTB"
        threat_id = "2147756452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MultiPlug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 85 3c ff ff ff c3 2f 51 48 c7 85 68 ff ff ff 1c e5 bb 64 c7 45 60 f1 85 f0 66 c7 45 e0 34 d1 53 63 c7 45 f0 07 d0 dc 4f c7 45 3c 03 cb be 53 0c 00 e8 ?? ?? ?? ?? c7 45 34}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MultiPlug_DA_2147786653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MultiPlug.DA!MTB"
        threat_id = "2147786653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MultiPlug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 0c 8b 16 02 c3 0f b6 c8 8b 45 08 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

