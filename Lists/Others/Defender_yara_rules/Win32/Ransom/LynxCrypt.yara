rule Ransom_Win32_LynxCrypt_PA_2147917405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LynxCrypt.PA!MTB"
        threat_id = "2147917405"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LynxCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".lynx" wide //weight: 1
        $x_1_2 = "README.txt" wide //weight: 1
        $x_1_3 = "\\background-image.jpg" wide //weight: 1
        $x_4_4 = "WW91ciBkYXRhIGlzIHN0b2xlbiBhbmQgZW5jcnlwdGVkLg0K" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

