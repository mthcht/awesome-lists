rule Ransom_Win32_Gocrypt_YA_2147731374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gocrypt.YA!MTB"
        threat_id = "2147731374"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gocrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ransomware/client" ascii //weight: 1
        $x_1_2 = "FILES_ENCRYPTED.htmlDesktop\\READ_TO_DECRYPT.html" ascii //weight: 1
        $x_1_3 = "Go build ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

