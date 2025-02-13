rule Trojan_Win32_Crstase_RS_2147833666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crstase.RS!MTB"
        threat_id = "2147833666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crstase"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 0f a2 89 45 fc 89 5d f8 89 4d ec 89 55 f0 b8 01 00 00 00 0f a2}  //weight: 1, accuracy: High
        $x_1_2 = "GetClipboardData" ascii //weight: 1
        $x_1_3 = "@.rep31" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

