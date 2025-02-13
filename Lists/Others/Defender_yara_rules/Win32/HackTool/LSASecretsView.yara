rule HackTool_Win32_LSASecretsView_BH_2147745244_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LSASecretsView.BH"
        threat_id = "2147745244"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LSASecretsView"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Policy\\PolSecretEncryptionKey" ascii //weight: 1
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "Software\\NirSoft\\LSASecretsView" ascii //weight: 1
        $x_1_4 = "\\Projects\\VS2005\\LSASecretsView\\Release\\LSASecretsView" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

