rule Trojan_Win32_Maui_RPJ_2147829272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maui.RPJ!MTB"
        threat_id = "2147829272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maui"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4d 10 33 45 10 d3 ff 03 7d 08 03 45 08 ff 4d f0 8a 0f 88 4d df 8a 08 88 0f 8a 4d df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

