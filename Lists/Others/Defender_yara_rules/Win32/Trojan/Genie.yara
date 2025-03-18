rule Trojan_Win32_Genie_A_2147936277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Genie.A!MTB"
        threat_id = "2147936277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Genie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 74 66 48 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 33 c0 89 08 50 45 43 6f 6d 70 61 63 74 32 00 7a b3 7d f7 64 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

