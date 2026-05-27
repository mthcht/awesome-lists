rule Trojan_Win64_VulnDriver_LVK_2147970346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VulnDriver.LVK!MTB"
        threat_id = "2147970346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VulnDriver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 0d 41 24 02 48 89 44 24 30 48 8d 05 f1 55 24 02 48 89 44 24 38 48 8d 05 1d 41 24 02 48 89 44 24 40 48 8d 05 f9 55 24 02 48 89 44 24 48 48 8d 05 25 41 24 02 48 89 44 24 50 48 8d 05 99 53 24 02 48 89 44 24 58 48 8d 05 55 41 24 02 48 89 44 24 60 48 8d 05 d9 55 24 02 48 89 44 24 68 48 8d 05 65 41 24 02 48 89 44 24 70 48 8d 05 01 56 24 02 48 89 44 24 78 48 8d 05 5d 41 24 02 48 89 45 80 48 8d 05 0a 56 24 02 48 89 45 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VulnDriver_LVL_2147970347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VulnDriver.LVL!MTB"
        threat_id = "2147970347"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VulnDriver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 97 81 24 02 48 89 45 d0 48 8d 05 0c 96 24 02 48 89 45 d8 48 8d 05 c9 81 24 02 48 89 45 e0 48 8d 05 2e 96 24 02 48 89 45 e8 48 8d 05 2b 82 24 02 48 89 45 f0 48 8d 05 50 96 24 02 48 89 45 f8 48 8d 05 bd 82 24 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

