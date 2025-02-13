rule Trojan_MSIL_Launcher_A_2147730466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Launcher.A!MTB"
        threat_id = "2147730466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Launcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\xnod32\\xnod32up.exe" wide //weight: 1
        $x_1_2 = "get_StartupPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Launcher_A_2147730466_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Launcher.A!MTB"
        threat_id = "2147730466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Launcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 28 1d 00 00 0a 26 de 0c 28 1e 00 00 0a 28 1f 00 00 0a de 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Launcher_SG_2147908718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Launcher.SG!MTB"
        threat_id = "2147908718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Launcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start robloxprocess.bat" ascii //weight: 1
        $x_1_2 = "hideit.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

