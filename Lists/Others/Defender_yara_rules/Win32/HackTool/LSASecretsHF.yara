rule HackTool_Win32_LSASecretsHF_B_2147901875_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LSASecretsHF.B"
        threat_id = "2147901875"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LSASecretsHF"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Policy\\PolSecretEncryptionKey" ascii //weight: 1
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "Software\\NirSoft\\LSASecretsView" ascii //weight: 1
        $x_1_4 = "\\Projects\\VS2005\\LSASecretsView\\Release\\LSASecretsView" ascii //weight: 1
        $x_1_5 = "riched20.dll" ascii //weight: 1
        $x_1_6 = "CryptDestroyHash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

