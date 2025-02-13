rule Trojan_Win32_Pterdo_YAI_2147913541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterdo.YAI!MTB"
        threat_id = "2147913541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterdo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 02 8b 4d ec 03 4d e0 0f b6 51 ff 33 c2 8b 4d ec 03 4d e0 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

