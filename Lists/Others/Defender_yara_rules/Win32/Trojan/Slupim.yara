rule Trojan_Win32_Slupim_A_2147605507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slupim.A"
        threat_id = "2147605507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slupim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c3 74 0d 8b c8 e8 ?? ?? ff ff 89 44 24 (14|18) eb 04 89 5c 24 (14|18) 6a 0c ?? 0f 00 00 00 68 ?? ?? ?? 00 8d 8c 24 ?? 00 00 00 89 ?? 24 ?? 00 00 00 89 9c 24 ?? 00 00 00 88 9c 24 ?? 00 00 00 e8 ?? ?? fe ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Slupim_B_2147620371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slupim.B"
        threat_id = "2147620371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slupim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 0d f0 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {ba 5c 00 00 00 b9 65 00 00 00 89}  //weight: 2, accuracy: High
        $x_2_3 = "\\\\.\\pipe\\$%d$" ascii //weight: 2
        $x_1_4 = "type=jpg&" ascii //weight: 1
        $x_1_5 = "HipImage" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

