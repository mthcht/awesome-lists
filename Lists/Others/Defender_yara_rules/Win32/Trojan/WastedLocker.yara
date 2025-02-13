rule Trojan_Win32_WastedLocker_VD_2147761137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WastedLocker.VD!MTB"
        threat_id = "2147761137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WastedLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 00 31 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WastedLocker_CB_2147767009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WastedLocker.CB"
        threat_id = "2147767009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WastedLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 fc 4a 06 00 68 f4 e0 01 00 e8}  //weight: 10, accuracy: High
        $x_10_2 = {bb 7f 0d 00 00 bb 7f 0d 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {c7 45 dc 01 00 00 00 c7 45 b4 01 00 00 00 c7 45 b8 01 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

