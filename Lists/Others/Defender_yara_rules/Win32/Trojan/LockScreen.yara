rule Trojan_Win32_LockScreen_C_2147716456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LockScreen.C!bit"
        threat_id = "2147716456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 8b 3d ?? ?? ?? ?? 81 e7 00 00 ff ff 0f b7 07 69 c0 ?? ?? ?? ?? 3d ?? ?? ?? ?? 74 1b}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 8f 00 00 ff ff 81 ef 00 00 01 00 69 c9 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 e5}  //weight: 1, accuracy: Low
        $x_1_3 = {34 0e 66 0f b6 c0 41 66 89 02 8a 01 83 c2 02 3c 0e 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LockScreen_YAAA_2147922145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LockScreen.YAAA!MTB"
        threat_id = "2147922145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "aHR0cDovLzIxMC4xMjcuMTg4LjI0MDo4MDgzL3dlbGNvbWUuZG8=" ascii //weight: 4
        $x_2_2 = "Ransomeware" ascii //weight: 2
        $x_2_3 = "isRansomePopup" ascii //weight: 2
        $x_1_4 = "ransomeEncPath" ascii //weight: 1
        $x_1_5 = "\\!!!!!README.txt" ascii //weight: 1
        $x_3_6 = "Origin Malware Start" ascii //weight: 3
        $x_3_7 = "Malware Running.." ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

