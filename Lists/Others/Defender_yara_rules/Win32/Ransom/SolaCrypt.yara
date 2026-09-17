rule Ransom_Win32_SolaCrypt_PA_2147978379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SolaCrypt.PA!MTB"
        threat_id = "2147978379"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SolaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".sola" ascii //weight: 3
        $x_1_2 = "%s\\README.txt" ascii //weight: 1
        $x_1_3 = "net stop cryptsvc > NUL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

