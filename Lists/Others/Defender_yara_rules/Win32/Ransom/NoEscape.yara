rule Ransom_Win32_NoEscape_MKV_2147848371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NoEscape.MKV!MTB"
        threat_id = "2147848371"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NoEscape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d1 03 c2 25 ?? ?? ?? ?? 79 ?? 48 0d ?? ?? ?? ?? 40 89 85 c8 fe ff ff 0f b6 84 05 e8 fe ff ff 88 84 3d e8 fe ff ff 8b 85 c8 fe ff ff 88 8c 05 e8 fe ff ff 0f b6 84 3d e8 fe ff ff 8b 8d c4 fe ff ff 03 c2 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 32 06 0f b6 c0 50 e8 ?? ?? ?? ?? 46 3b b5 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_NoEscape_YAA_2147888510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NoEscape.YAA!MTB"
        threat_id = "2147888510"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NoEscape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 8b 4d 84 c1 c0 0d 33 c8 8b 45 a4 03 c1 89 4d 84 c1 c0 12 33 d0 8b 4d a0 8b 45 b4 03 c6 c1 c0 07 33 c8 8b 45 b4 03 c1 89 4d a0 c1 c0 09 31 45 ac 8b 45 ac 03 c1 8b 4d 94 c1 c0 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_NoEscape_SA_2147889068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NoEscape.SA!MTB"
        threat_id = "2147889068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NoEscape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network has been hacked and infected by NoEscape" ascii //weight: 1
        $x_1_2 = "HOW_TO_RECOVER_FILES.txt" ascii //weight: 1
        $x_1_3 = "We are not a politically company and we are not interested in your private affairs" ascii //weight: 1
        $x_1_4 = "powershell Dismount-DiskImage -ImagePath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

