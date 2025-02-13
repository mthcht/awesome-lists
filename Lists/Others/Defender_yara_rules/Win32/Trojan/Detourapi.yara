rule Trojan_Win32_Detourapi_A_2147624638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detourapi.A"
        threat_id = "2147624638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detourapi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a ff ff 15 ?? ?? 40 00 c6 05 ?? ?? 40 00 68 c6 05 ?? ?? 40 00 c3 c7 05 ?? ?? 40 00 87 27 40 00 8d 55 fc 52 6a 06}  //weight: 1, accuracy: Low
        $x_1_2 = {ac 08 c0 74 07 34 9b 90 aa 90 e2 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

