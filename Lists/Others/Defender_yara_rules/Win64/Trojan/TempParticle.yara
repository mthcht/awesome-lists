rule Trojan_Win64_TempParticle_A_2147816926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TempParticle.A!dha"
        threat_id = "2147816926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TempParticle"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {44 2b c3 c6 03 e9 41 83 e8 05 ba 0a 00 00 00 44 89 43 01 48 8b cb 44 ?? ?? ?? ?? ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

