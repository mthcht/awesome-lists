rule Trojan_Win32_Loyeetro_DSK_2147742600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loyeetro.DSK!MTB"
        threat_id = "2147742600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loyeetro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 08 03 88 55 fe 8a 45 fe 88 45 ff c0 65 ff 02 0f b6 4d ff 81 e1 c0 00 00 00 88 4d ff 0f b6 55 fd 0f b6 45 ff 0b d0 88 55 fd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

