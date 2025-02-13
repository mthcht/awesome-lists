rule Trojan_Win32_plugx_2147842174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/plugx.psyC!MTB"
        threat_id = "2147842174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "plugx"
        severity = "Critical"
        info = "psyC: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {07 08 9a 0d 09 6f 15 00 00 0a 72 01 00 00 70 28 16 00 00 0a 2c 28 09 6f 17 00 00 0a 20 0e 00 02 00 12 00 28 01 00 00 06 2d 01 2a 06 28 03 00 00 06 26 09 6f 17 00 00 0a 28 02 00 00 06 26 08 17 58 0c 08}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

