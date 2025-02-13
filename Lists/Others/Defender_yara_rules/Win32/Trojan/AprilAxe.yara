rule Trojan_Win32_AprilAxe_C_2147818939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AprilAxe.C!dha"
        threat_id = "2147818939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AprilAxe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {8b 84 3e fc 0f 00 00 8d 84 30 00 10 00 00 89 85 ?? ?? ?? ?? 3b fb 74 ?? 8d 86 00 10 00 00 89}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AprilAxe_D_2147823426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AprilAxe.D!dha"
        threat_id = "2147823426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AprilAxe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 03 45 f8 8b 4d 0c 8a 11 88 10 8b 45 f8 83 c0 01 89 45 f8 ?? 4d 0c 83 c1 02 89 4d 0c 8b 55 0c 0f b7 02 85 c0 75 d7 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

