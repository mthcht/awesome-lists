rule Ransom_Win32_KarmaLocker_PAA_2147795539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KarmaLocker.PAA!MTB"
        threat_id = "2147795539"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KarmaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WW91ciBuZXR3b3JrIGhhcyBiZWVuIGJyZWFjaGVkIGJ5IEthcm1hIHJhbnNvbXdhcmUgZ3J" wide //weight: 1
        $x_1_2 = "READ KARMA-ENCRYPTED" wide //weight: 1
        $x_1_3 = ":\\aaa_TouchMeNot_.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

