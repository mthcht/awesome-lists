rule Trojan_Win32_Darkgate_IP_2147895643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkgate.IP!MTB"
        threat_id = "2147895643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkgate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii //weight: 1
        $x_1_2 = {8a 1a 8a 4e 06 eb e8 8a 5c 31 06 32 1c 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Darkgate_YAB_2147928173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkgate.YAB!MTB"
        threat_id = "2147928173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkgate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 d8 83 c0 ?? 48 48 48 48}  //weight: 1, accuracy: Low
        $x_10_2 = {48 48 48 58 31 d2 f7 f3 8a 04 16 30 04 0f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Darkgate_YAC_2147932096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkgate.YAC!MTB"
        threat_id = "2147932096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkgate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {2d 67 12 13 00 01 87 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 33 87 ?? ?? ?? ?? 83 e8 ?? 31 87 ?? ?? ?? ?? 8b 87 ?? ?? ?? ?? 0f af 87}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Darkgate_YAD_2147932828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkgate.YAD!MTB"
        threat_id = "2147932828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkgate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {61 30 04 0f 66 0f 57 c9 41 f2 0f 5f c8 89 c8 66 0f 55 c1}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

