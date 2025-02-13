rule Trojan_Win32_Xnet_ARAZ_2147928286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xnet.ARAZ!MTB"
        threat_id = "2147928286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 fc 8b 45 08 01 c2 8b 4d fc 8b 45 08 01 c8 0f b6 00 32 45 ec 88 02 83 45 fc 01 8b 45 fc 3b 45 0c 7c dc}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

