rule Ransom_Win32_CaesarCrypt_PA_2147915504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CaesarCrypt.PA!MTB"
        threat_id = "2147915504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CaesarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\README.TXT" ascii //weight: 1
        $x_1_2 = "All Your Files Is Encrypted Now" ascii //weight: 1
        $x_2_3 = "We Are Caesar. We Operate a Ransomware Operation!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

