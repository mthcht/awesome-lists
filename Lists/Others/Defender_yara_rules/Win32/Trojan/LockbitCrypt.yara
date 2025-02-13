rule Trojan_Win32_LockbitCrypt_SA_2147763544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LockbitCrypt.SA!MTB"
        threat_id = "2147763544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LockbitCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fb c1 e7 04 81 3d ?? ?? ?? ?? 6f 03 00 00 75 0a 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 8b f3 c1 ee 05 03 75 ?? 03 f9 03 d3 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 40 50 52 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LockbitCrypt_SA_2147763544_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LockbitCrypt.SA!MTB"
        threat_id = "2147763544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LockbitCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d fc 8b fb c1 e7 04 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 8b f3 c1 ee 05 03 75 ?? 03 f9 03 d3 33 fa 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 64 24 00 81 f9 ?? ?? ?? ?? 75 ?? 8b 15 ?? ?? ?? ?? 8d 4c 24 ?? 51 6a 40 50 52 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 ?? 33 c0 33 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LockbitCrypt_SB_2147780181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LockbitCrypt.SB!MTB"
        threat_id = "2147780181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LockbitCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 49 00 6a 00 6a 00 6a 00 ff d6 83 ef 01 c7 05 ?? ?? ?? ?? 00 00 00 00 75 0d 00 56 8b 35 ?? ?? ?? ?? 57 bf}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 81 fe ?? ?? ?? ?? 75 ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d7 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {51 6a 40 50 52 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

