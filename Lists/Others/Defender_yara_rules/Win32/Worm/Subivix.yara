rule Worm_Win32_Subivix_2147603679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Subivix.gen!dll"
        threat_id = "2147603679"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Subivix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 42 be 01 00 00 00 8b 45 fc 8a 5c 30 ff 8b c6 25 01 00 00 80 79 05 48 83 c8 fe 40 85 c0 75 05 80 eb 05 eb 03 80 eb 06 8d 45 f4 8b d3 e8 ?? ?? ff ff 8b 55 f4 8b 45 f8 e8 ?? ?? ff ff 8b 45 f8 46 4f 75 c3}  //weight: 2, accuracy: Low
        $x_1_2 = "nyzu@45" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Subivix_2147603680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Subivix"
        threat_id = "2147603680"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Subivix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 1, accuracy: Low
        $x_1_2 = {66 83 f8 03 74 0c 66 83 f8 04 74 06 66 83 f8 02 75 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

