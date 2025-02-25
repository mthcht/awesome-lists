rule Trojan_Win64_CorporalStomp_A_2147934372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CorporalStomp.A!dha"
        threat_id = "2147934372"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CorporalStomp"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 36 08 fd 00 e8 ?? ?? ff ff ba 1a 44 fd 00 8b f0 e8 ?? ?? ff ff ba eb b2 09 00 89 45 ?? e8 ?? ?? ff ff ba a3 97 fc 00 89 45 ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

