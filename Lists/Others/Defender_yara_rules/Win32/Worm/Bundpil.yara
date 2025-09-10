rule Worm_Win32_Bundpil_ASFG_2147904264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundpil.ASFG!MTB"
        threat_id = "2147904264"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4a 81 ca 00 ff ff ff 42 89 95 ?? ?? ff ff 8b 55 fc 03 95 ?? ?? ff ff 0f b6 02 8b 8d ?? ?? ff ff 0f b6 91 ?? ?? ?? ?? 33 c2 8b 4d ?? 03 8d ?? ?? ff ff 88 01 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Bundpil_GTT_2147930727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundpil.GTT!MTB"
        threat_id = "2147930727"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 0f b6 93 ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 32 14 03 41 81 e1 ff ?? ?? ?? 88 10 79}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Bundpil_AWIA_2147930844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundpil.AWIA!MTB"
        threat_id = "2147930844"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 43 8a 83 ?? ?? ?? ?? 32 04 0a 41 ff 8d ?? ?? ?? ?? 88 41 ff 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Bundpil_AXIA_2147930967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundpil.AXIA!MTB"
        threat_id = "2147930967"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {43 0f b6 93 ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 32 14 03 46 81 e6 ?? ?? ?? ?? 88 10 79}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Bundpil_GXT_2147951756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundpil.GXT!MTB"
        threat_id = "2147951756"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 0f b6 96 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 32 14 3e 8d 70 01 81 e6 ff ?? ?? ?? 88 17}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Bundpil_GXU_2147951915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundpil.GXU!MTB"
        threat_id = "2147951915"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 0f b6 9f ?? ?? ?? ?? 8b bd ?? ?? ?? ?? 32 1c 37 40 25 ff 00 00 80 88 1e}  //weight: 10, accuracy: Low
        $x_10_2 = {03 d0 81 e2 ?? ?? ?? ?? ?? ?? 4a 81 ca ?? ?? ?? ?? 42 0f b6 92 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 32 54 38 03 83 c7 ?? 88 51 ?? 83 c1 ?? 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

