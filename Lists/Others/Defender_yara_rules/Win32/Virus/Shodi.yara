rule Virus_Win32_Shodi_J_2147709417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Shodi.J!bit"
        threat_id = "2147709417"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Shodi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oobb.exe" ascii //weight: 1
        $x_1_2 = {61 6d 73 00 6f 67 72 00 53 68 6f 68 64 69 57 69 74 68 50 72 6f 67 72 61 6d 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Shodi_F_2147905394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Shodi.F!MTB"
        threat_id = "2147905394"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Shodi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 44 24 28 50 53 53 68 99 19 40 00 68 00 04 00 00 53 ff 15 04 30 40 00 89 c7 53 57 ff d5 85 c0 74 de 6a 64 ff d6 57 ff 15 00 30 40 00 68 84 03 00 00 ff d6 57 ff 15 48 30 40 00 eb dd}  //weight: 1, accuracy: High
        $x_1_2 = "USR_Shohdi_Photo_USR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

