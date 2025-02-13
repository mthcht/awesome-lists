rule Ransom_Win64_Nekark_MX_2147927895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nekark.MX!MTB"
        threat_id = "2147927895"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 1
        $x_1_2 = "WMIC.exe shadowcopy" wide //weight: 1
        $x_1_3 = "Your files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

