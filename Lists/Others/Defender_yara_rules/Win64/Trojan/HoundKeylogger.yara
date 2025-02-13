rule Trojan_Win64_HoundKeylogger_A_2147892447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HoundKeylogger.A!MTB"
        threat_id = "2147892447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HoundKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 b9 88 ff ff ff 48 89 5c 24 20 45 33 c0 33 d2 b9 00 08 00 00 ff 15 ?? ?? ?? ?? b9 01 00 00 00 ff 15 ?? ?? ?? ?? b9 05 00 00 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

