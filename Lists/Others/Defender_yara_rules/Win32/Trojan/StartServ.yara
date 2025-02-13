rule Trojan_Win32_StartServ_AC_2147817454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartServ.AC!MTB"
        threat_id = "2147817454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartServ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

