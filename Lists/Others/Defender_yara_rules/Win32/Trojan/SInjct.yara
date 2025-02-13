rule Trojan_Win32_SInjct_2147795794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SInjct!MTB"
        threat_id = "2147795794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SInjct"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 49 89 ca 0f 05}  //weight: 1, accuracy: High
        $x_1_2 = {41 59 41 58 5a 59 49 89 ca 0f 05}  //weight: 1, accuracy: High
        $x_1_3 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 [0-5] 48 8b 48 10 [0-5] 4c 8b 59 30}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 8c 24 ?? ?? ?? ?? 83 ca ff ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

