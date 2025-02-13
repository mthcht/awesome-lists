rule Trojan_Win32_MagicRAT_RS_2147833668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MagicRAT.RS!MTB"
        threat_id = "2147833668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MagicRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MagicMon\\MagicSystem.ini" wide //weight: 1
        $x_1_2 = "veryveruniquekey" wide //weight: 1
        $x_1_3 = "uBatkBopoBrah" wide //weight: 1
        $x_1_4 = "L0FwcERhdGEvUm9hbW" ascii //weight: 1
        $x_1_5 = "success self delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

