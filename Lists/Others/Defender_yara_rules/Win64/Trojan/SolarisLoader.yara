rule Trojan_Win64_SolarisLoader_ASL_2147972958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SolarisLoader.ASL!MTB"
        threat_id = "2147972958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SolarisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 c0 75 0e 48 8b cf ff 15 ?? ?? ?? ?? 48 85 c0 74 6a 48 8b d6 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 74 56 ba 08 00 00 00 4c 8d 4c 24 30 48 8b c8 44 8d 42 38}  //weight: 1, accuracy: Low
        $x_2_2 = {66 c7 44 24 3c 80 c3 41 8d 50 06 49 63 c8 41 ff c0 8a 44 0c 38 88 04 19 44 3b c2 72 ee 44 8b 44 24 30 4c 8d 4c 24 30 48 8b cb ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SolarisLoader_AB_2147981684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SolarisLoader.AB!MTB"
        threat_id = "2147981684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SolarisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {80 39 68 4c 8b c9 41 8b f0 41 8b d8 0f 85 3d 01 00 00 80 79 01 74 0f 85 33 01 00 00 80 79 02 74 0f 85 29 01 00 00 80 79 03 70 0f 85 1f 01 00 00 80 79 04 3a 0f 85 15 01 00 00 80 79 05 2f 0f 85 0b 01 00 00 80 79 06 2f 0f 85 01 01 00 00 48 8d 51 07 8a 0a 45 8d 58 07 84 c9 74 37 49 8d 78 f9 49 2b f9 80 f9 2f 74 2b 80 f9 3a 74 26 48 8d 04 17 ff c6 48 ff c2 42 88 0c 10 41 ff c3 48 8d 04 17 48 3d 07 01 00 00 0f 8d c2 00 00 00 8a 0a 84 c9 75 d0}  //weight: 6, accuracy: High
        $x_2_2 = "SHGetFolderPathWNtReadVirtualMem" ascii //weight: 2
        $x_2_3 = "stgtier.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SolarisLoader_MK_2147982110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SolarisLoader.MK!MTB"
        threat_id = "2147982110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SolarisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b ca ff c2 42 0f b6 04 01 66 89 44 4c 20 46 38 2c 02 ?? ?? 8b c2 48 8d 4c 24 20 66 44 89 6c 44 20}  //weight: 20, accuracy: Low
        $x_15_2 = {48 8b c8 48 2b f8 8b d6 8a 04 0f 34 0d 88 01 48 ff c1 48 83 ea 01}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

