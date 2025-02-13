rule Trojan_Win32_Jalapeno_ARA_2147927387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jalapeno.ARA!MTB"
        threat_id = "2147927387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "New victim from gtbuilder 1.0 IP Address:" wide //weight: 2
        $x_2_2 = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTI" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

