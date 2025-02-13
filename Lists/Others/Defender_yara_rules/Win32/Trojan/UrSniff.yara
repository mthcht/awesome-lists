rule Trojan_Win32_UrSniff_RPX_2147830032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSniff.RPX!MTB"
        threat_id = "2147830032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSniff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 8b d6 2b 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 03 d1 8d 81 37 ff ff ff 3d b9 0e 00 00 8b fb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 10 05 0c d7 85 01 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

