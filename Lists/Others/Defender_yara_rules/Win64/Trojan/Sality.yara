rule Trojan_Win64_Sality_MA_2147925518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sality.MA!MTB"
        threat_id = "2147925518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TrustedInstaller" ascii //weight: 1
        $x_1_2 = "10.0.17134.1304" wide //weight: 1
        $x_1_3 = "Windows Modules Installer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

