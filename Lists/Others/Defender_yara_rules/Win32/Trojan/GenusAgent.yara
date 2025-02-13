rule Trojan_Win32_GenusAgent_JL_2147837991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenusAgent.JL!MTB"
        threat_id = "2147837991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenusAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 10 27 00 00 ff 15 00 c0 ?? ?? 33 c0 c2 10 00 3b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {a8 00 00 00 7e 00 00 00 00 00 00 5f 12 00 00 00 10 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

