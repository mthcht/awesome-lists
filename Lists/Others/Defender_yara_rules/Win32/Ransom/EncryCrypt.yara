rule Ransom_Win32_EncryCrypt_PA_2147976851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EncryCrypt.PA!MTB"
        threat_id = "2147976851"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EncryCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".encry" wide //weight: 1
        $x_4_2 = "!HELP_YOUR_FILES.HTML" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

