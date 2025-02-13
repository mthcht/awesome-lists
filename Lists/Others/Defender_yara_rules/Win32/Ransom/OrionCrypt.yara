rule Ransom_Win32_OrionCrypt_PA_2147778704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/OrionCrypt.PA!MTB"
        threat_id = "2147778704"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "OrionCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OrionRansomware.exe" wide //weight: 1
        $x_1_2 = "%userappdata%\\RestartApp.exe" ascii //weight: 1
        $x_1_3 = "contact info@oreans.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

