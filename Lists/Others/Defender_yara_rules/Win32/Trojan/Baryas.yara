rule Trojan_Win32_Baryas_MBWP_2147930894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Baryas.MBWP!MTB"
        threat_id = "2147930894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Baryas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 39 61 00 68 ?? 29 61 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15 5c 35 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Baryas_MBWQ_2147931079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Baryas.MBWQ!MTB"
        threat_id = "2147931079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Baryas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? ab 63 00 68 ?? 42 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? a6 63 00 33 d2 8a d4 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

