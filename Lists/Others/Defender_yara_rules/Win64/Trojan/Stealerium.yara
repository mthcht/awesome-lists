rule Trojan_Win64_Stealerium_ASR_2147971961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealerium.ASR!MTB"
        threat_id = "2147971961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 48 8d 0d 62 3c 00 00 48 8d 15 4e 4e 00 00 44 8a 04 08 41 80 f0 1b 44 88 04 10 48 ff c0 48 83 f8 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

