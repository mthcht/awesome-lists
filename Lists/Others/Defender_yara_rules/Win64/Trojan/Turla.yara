rule Trojan_Win64_Turla_A_2147731731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Turla.A!dha"
        threat_id = "2147731731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CVRG72B5.tmp.cvr" ascii //weight: 1
        $x_1_2 = "KernelInjector::FindDllImageBase" wide //weight: 1
        $x_1_3 = "{531511FA-190D-5D85-8A4A-279F2F592CC7}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Turla_AG_2147821028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Turla.AG!MSR"
        threat_id = "2147821028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "D:\\rustproject\\shellcode\\02-ecw\\target\\release\\deps\\Yihsiwei.pdb" ascii //weight: 2
        $x_2_2 = "fz4883e4fye8z8yyyyyy4151415y5251564831d265488b526y488b52184" ascii //weight: 2
        $x_1_3 = "GetEnvironmentVariableW" ascii //weight: 1
        $x_1_4 = "WriteConsoleW" ascii //weight: 1
        $x_1_5 = "WriteFile" ascii //weight: 1
        $x_1_6 = "GetTempPath2W" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

