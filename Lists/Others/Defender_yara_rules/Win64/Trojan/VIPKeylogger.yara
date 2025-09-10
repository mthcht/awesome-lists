rule Trojan_Win64_VIPKeylogger_2147951968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VIPKeylogger.MTH!MTB"
        threat_id = "2147951968"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b ca 41 b8 00 30 00 00 48 8b d1 33 c9 48 ff 25 bb 5f 06 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

