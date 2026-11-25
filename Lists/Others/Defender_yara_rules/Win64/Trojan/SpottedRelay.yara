rule Trojan_Win64_SpottedRelay_B_2147982738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpottedRelay.B!dha"
        threat_id = "2147982738"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpottedRelay"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 73 00 65 00 74 00 75 00 70 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

