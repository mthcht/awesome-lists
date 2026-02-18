rule Trojan_Win32_Polyransom_SG_2147907024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polyransom.SG!MTB"
        threat_id = "2147907024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e9 00 00 00 00 32 c2 88 07 ?? ?? ?? ?? ?? ?? 83 f9 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Polyransom_RMX_2147962961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polyransom.RMX!MTB"
        threat_id = "2147962961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {46 90 47 90 49 83 f9 00 90 0f 85}  //weight: 2, accuracy: High
        $x_2_2 = {8a 06 90 32 c2 90 88 07 46 90 47 49}  //weight: 2, accuracy: High
        $x_2_3 = {32 c2 88 07 90 46 47 49 90 83 f9 00 90}  //weight: 2, accuracy: High
        $x_2_4 = {88 07 90 42 46 47 90 49 83 f9 00 90 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Polyransom_RAMX_2147963216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polyransom.RAMX!MTB"
        threat_id = "2147963216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 90 88 07 90 42 46 47 90 49}  //weight: 2, accuracy: High
        $x_2_2 = {32 c2 90 88 07 46 47 49 83 f9 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Polyransom_RBMX_2147963217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polyransom.RBMX!MTB"
        threat_id = "2147963217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 90 32 c2 88 07 42 46 90 47 90}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

