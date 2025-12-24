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

