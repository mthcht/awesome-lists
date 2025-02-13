rule Ransom_Win32_Trinity_ATR_2147911406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Trinity.ATR!MTB"
        threat_id = "2147911406"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Trinity"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d3 03 7d d8 c1 c2 10 03 ca 89 4d 08 33 4d c8 c1 c1 0c 03 d9 33 d3 89 5d ec 8b 5d 08 c1 c2 08}  //weight: 1, accuracy: High
        $x_1_2 = {6a 0a 68 c1 00 00 00 6a 00 ff d7 8b f0 85 f6 0f 84 ?? ?? ?? ?? 56 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

