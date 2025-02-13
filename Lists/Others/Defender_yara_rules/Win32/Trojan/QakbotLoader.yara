rule Trojan_Win32_QakbotLoader_2147813748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotLoader!MTB"
        threat_id = "2147813748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 02 c3 32 c3 aa e2 ?? 5e 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {ac 84 c0 74 ?? 32 d0 c1 c2 ?? eb ?? 8b c2 5e 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

