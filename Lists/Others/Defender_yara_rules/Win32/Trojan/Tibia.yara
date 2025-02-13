rule Trojan_Win32_Tibia_GCX_2147839961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibia.GCX!MTB"
        threat_id = "2147839961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 8a 5c 30 ff 8d 45 e8 33 d2 8a d3 8b 4d f0 33 d1 e8 ?? ?? ?? ?? 8b 55 e8 8d 45 ec e8 ?? ?? ?? ?? 46 4f 75}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Drivers\\Etc\\Hosts" ascii //weight: 1
        $x_1_3 = "tibiaclient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

