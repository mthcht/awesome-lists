rule Trojan_Win32_ClaimLoader_GVA_2147954614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClaimLoader.GVA!MTB"
        threat_id = "2147954614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClaimLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WHelp_Intall_XOX.dll" ascii //weight: 2
        $x_1_2 = "CLSD_UUIDC_NewYueiot" wide //weight: 1
        $x_1_3 = "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X" wide //weight: 1
        $x_1_4 = "QKFJSGCGWGRQ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClaimLoader_GVB_2147954615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClaimLoader.GVB!MTB"
        threat_id = "2147954615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClaimLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 83 e1 03 8a 0c 8d ?? ?? ?? ?? 30 4c 04 68 40 3b c2 7c eb}  //weight: 2, accuracy: Low
        $x_1_2 = {73 09 80 34 08 19 40 3b c2 72 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

