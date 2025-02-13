rule Ransom_Win32_Standartlocker_DA_2147772308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Standartlocker.DA!MTB"
        threat_id = "2147772308"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Standartlocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LIST OF YOUR ENCRYPTED FILES" ascii //weight: 1
        $x_1_2 = "@protonmail.com" ascii //weight: 1
        $x_1_3 = "Standart locker" ascii //weight: 1
        $x_1_4 = "bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

