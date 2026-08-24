rule Trojan_Win32_RogueDialer_ARA_2147976840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RogueDialer.ARA!MTB"
        threat_id = "2147976840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RogueDialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 8d 85 c8 fe ff ff 50 57 53 56 ff 75 e4 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = "dialers@wts-company.ch" ascii //weight: 2
        $x_1_3 = "RasDialA" ascii //weight: 1
        $x_1_4 = "RasSetEntryPropertiesA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

