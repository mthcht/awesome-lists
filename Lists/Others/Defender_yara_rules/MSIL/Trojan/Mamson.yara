rule Trojan_MSIL_Mamson_CG_2147778971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamson.CG!MTB"
        threat_id = "2147778971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamson"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0a 06 6f 43 ?? ?? 0a 03 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 17 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
        $x_3_2 = "LUNCHER CRACKING" ascii //weight: 3
        $x_3_3 = "runas" ascii //weight: 3
        $x_3_4 = "ExecuteAsAdmin" ascii //weight: 3
        $x_3_5 = "carpeta" ascii //weight: 3
        $x_3_6 = "get_StartupPath" ascii //weight: 3
        $x_3_7 = "Launcher.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

