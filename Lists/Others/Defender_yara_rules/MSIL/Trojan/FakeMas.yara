rule Trojan_MSIL_FakeMas_DA_2147960736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeMas.DA!MTB"
        threat_id = "2147960736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeMas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {5c 67 68 6f 73 74 5c 4c 6f 61 64 65 72 5c 6f 62 6a 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6e 65 74 [0-15] 5c 4c 6f 61 64 65 72 2e 70 64 62}  //weight: 20, accuracy: Low
        $x_1_2 = "InvokeBowInnSki" ascii //weight: 1
        $x_1_3 = "DLLFromMemory" ascii //weight: 1
        $x_1_4 = "Loader.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FakeMas_DB_2147960737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeMas.DB!MTB"
        threat_id = "2147960737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeMas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "cmd.exe exclusion added to Windows Defender" ascii //weight: 20
        $x_1_2 = "svminerloader.Properties.Resources" ascii //weight: 1
        $x_1_3 = "DLLFromMemory" ascii //weight: 1
        $x_1_4 = "InvokeMiner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

