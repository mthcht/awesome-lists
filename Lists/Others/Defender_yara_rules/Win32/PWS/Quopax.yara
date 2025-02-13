rule PWS_Win32_Quopax_A_2147626304_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Quopax.A"
        threat_id = "2147626304"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Quopax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 68 6c ee ff ff 56 ff 15 ?? ?? ?? 00 68 94 11 00 00 e8 ?? ?? 00 00 83 c4 04 8b f8 8d 45 fc 6a 00 50 68 94 11 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 7c 56 e8 ?? ?? 00 00 6a 24 56 8b f8 e8 ?? ?? 00 00 8b d8 6a 40 56 89 5d fc e8 ?? ?? 00 00 6a 23 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Quopax_A_2147626305_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Quopax.A!dll"
        threat_id = "2147626305"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Quopax"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 ?? ?? ?? 10 68 00 04 00 00 e8 ?? ?? ?? 00 83 c4 04 8b f8 8d 44 24 08 6a 00 50 68 00 04 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 b8 0b 00 00 ff d7 8d 85 ?? ?? ff ff 50 ff d3 85 c0 75 ?? 46 83 fe 19 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

