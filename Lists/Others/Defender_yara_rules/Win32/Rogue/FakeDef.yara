rule Rogue_Win32_FakeDef_194688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeDef"
        threat_id = "194688"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeDef"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/api/ping?stage=3&uid=%S" wide //weight: 1
        $x_1_2 = "%s/billing/key/?uid=%S" wide //weight: 1
        $x_1_3 = "{red}INFECTED: {inf}{}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeDef_194688_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeDef"
        threat_id = "194688"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeDef"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?stage=1&uid=%S&id=%d&subid=%d&os=%d" wide //weight: 1
        $x_1_2 = {ff 50 04 89 45 fc 83 7d fc 00 0f 84 ?? ?? 00 00 8b 45 ?? 83 c0 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeDef_194688_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeDef"
        threat_id = "194688"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeDef"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Microsoft\\Microsoft Antimalware" wide //weight: 1
        $x_1_2 = "/ping?stage=1&uid=%S&id=%d&subid=%d&os=%d" wide //weight: 1
        $x_1_3 = "/ping?stage=3&uid=%S&exec=%d" wide //weight: 1
        $x_1_4 = {bf 19 00 02 00 57 33 db 53 68 ?? ?? ?? ?? 68 02 00 00 80 ff d6 85 c0 0f ?? ?? ?? ?? ?? 8d ?? ?? 50 57 53 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

