rule Trojan_Win32_SpyShiz_RE_2147844716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyShiz.RE!MTB"
        threat_id = "2147844716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyShiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 07 03 15 ?? ?? ?? ?? c1 c2 04 2b 15 ?? ?? ?? ?? c1 c2 06 8b c2 d1 e8 c1 c0 03 2b c3 89 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyShiz_MX_2147926201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyShiz.MX!MTB"
        threat_id = "2147926201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyShiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\oil\\feet\\Seven\\Send\\Gather\\Dividerail.pdb" ascii //weight: 1
        $x_1_2 = "listen above" wide //weight: 1
        $x_1_3 = "familycould cost" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyShiz_MX_2147926201_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyShiz.MX!MTB"
        threat_id = "2147926201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyShiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "websocket.dll" wide //weight: 1
        $x_1_2 = "10.0.17134.1" wide //weight: 1
        $x_1_3 = "listen above" wide //weight: 1
        $x_1_4 = "familycould cost" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

