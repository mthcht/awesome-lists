rule Ransom_Win32_GoCrypt_PAB_2147797720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GoCrypt.PAB!MTB"
        threat_id = "2147797720"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptor" ascii //weight: 1
        $x_1_2 = "!!! DANGER !!!" ascii //weight: 1
        $x_1_3 = "WINNER WINNER CHICKEN DINNER" ascii //weight: 1
        $x_1_4 = "All your servers and computers are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

