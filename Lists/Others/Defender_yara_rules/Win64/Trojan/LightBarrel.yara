rule Trojan_Win64_LightBarrel_A_2147974506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LightBarrel.A!dha"
        threat_id = "2147974506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LightBarrel"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ba 59 45 49 44 4e 45 4b 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

