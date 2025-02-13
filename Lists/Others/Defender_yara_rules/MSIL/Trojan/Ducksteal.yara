rule Trojan_MSIL_Ducksteal_SK_2147834142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ducksteal.SK!MTB"
        threat_id = "2147834142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ducksteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libbridged.exe" ascii //weight: 1
        $x_1_2 = "\\rhc.exe" ascii //weight: 1
        $x_1_3 = "php.exe index.php" ascii //weight: 1
        $x_1_4 = "UpdaterTriggerPHP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ducksteal_SL_2147834143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ducksteal.SL!MTB"
        threat_id = "2147834143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ducksteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$db0739ae-8e19-4387-8627-5c901b0e3d3e" ascii //weight: 1
        $x_1_2 = "E:\\Workspace\\Projects\\scancookieserver2\\ToolsCheckCookie\\CUnProtectData\\obj\\Release\\cunprotectdata.pdb" ascii //weight: 1
        $x_1_3 = "cunprotectdata.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

