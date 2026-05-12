rule Trojan_Win64_Valleyrat_YBE_2147960012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valleyrat.YBE!MTB"
        threat_id = "2147960012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valleyrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" wide //weight: 1
        $x_1_3 = "VenkernalData_info" wide //weight: 1
        $x_1_4 = "C:\\Users\\Public\\venwin.lock" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Valleyrat_YBG_2147960013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valleyrat.YBG!MTB"
        threat_id = "2147960013"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valleyrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "Global\\xfolder32_svchost64_mutex" wide //weight: 1
        $x_1_3 = "C:\\ProgramData\\xfolder32\\svchost64.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Valleyrat_ARY_2147969123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valleyrat.ARY!MTB"
        threat_id = "2147969123"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valleyrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 0f af c2 4d 31 c8 4c 89 44 24 60 48 83 c2 01 48 89 54 24 68 4c 8b 44 24 68 42 8a 14 01 4c 8b 4c 24 60 45 88 ca 44 30 d2 44 0f b6 d2}  //weight: 1, accuracy: High
        $x_2_2 = {8b 44 24 30 48 8b 4c 24 58 8a 54 24 37 44 8a 44 24 2d 41 30 d0 44 88 44 24 27 48 63 d0 44 88 04 11 83 c0 01 89 44 24 28 83 f8 14 74 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

