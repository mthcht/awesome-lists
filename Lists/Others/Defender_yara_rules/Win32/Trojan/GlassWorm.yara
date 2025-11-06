rule Trojan_Win32_GlassWorm_EM_2147956195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GlassWorm.EM!MTB"
        threat_id = "2147956195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "generate_secret_key_hvnc.pdb" ascii //weight: 1
        $x_1_2 = "generate_secret_key_hvnc.dll" ascii //weight: 1
        $x_1_3 = "napi_register_module_v1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GlassWorm_B_2147956903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GlassWorm.B!MTB"
        threat_id = "2147956903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eval(atob(" wide //weight: 1
        $x_1_2 = "node.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

