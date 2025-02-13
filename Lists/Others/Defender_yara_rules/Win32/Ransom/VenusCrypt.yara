rule Ransom_Win32_VenusCrypt_PAA_2147798042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VenusCrypt.PAA!MTB"
        threat_id = "2147798042"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VenusCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".venus" ascii //weight: 1
        $x_1_2 = "README.txt" ascii //weight: 1
        $x_1_3 = "help2021me@aol.com" ascii //weight: 1
        $x_1_4 = "files has been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

