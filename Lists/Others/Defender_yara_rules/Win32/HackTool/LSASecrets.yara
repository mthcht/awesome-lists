rule HackTool_Win32_LSASecrets_HF_2147892114_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LSASecrets.HF"
        threat_id = "2147892114"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LSASecrets"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Policy\\PolSecretEncryptionKey" ascii //weight: 1
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "Software\\NirSoft\\LSASecretsView" ascii //weight: 1
        $x_1_4 = "\\Projects\\VS2005\\LSASecretsView\\Release\\LSASecretsView" ascii //weight: 1
        $x_1_5 = "riched20.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

