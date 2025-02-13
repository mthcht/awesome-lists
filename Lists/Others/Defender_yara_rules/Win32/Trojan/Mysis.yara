rule Trojan_Win32_Mysis_A_2147717895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mysis.A"
        threat_id = "2147717895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mysis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ddos.tf" ascii //weight: 1
        $x_1_2 = "invest.f3322.net" ascii //weight: 1
        $x_1_3 = "Windows Help System Myss" ascii //weight: 1
        $x_2_4 = {6a 12 56 53 e8 ?? ?? ?? ?? c6 85 ?? ?? ff ff 47 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 57 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 77 c6 85 ?? ?? ff ff 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mysis_B_2147718221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mysis.B!bit"
        threat_id = "2147718221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mysis"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ddos.tf" ascii //weight: 1
        $x_1_2 = "Windows Help System Myss" ascii //weight: 1
        $x_1_3 = "%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_4 = {56 ff 15 74 b4 41 00 8b f0 e8 ?? ?? ?? ?? 83 c0 03 33 d2 0f af c6 f7 74 24 08 5e 8b c2}  //weight: 1, accuracy: Low
        $x_2_5 = {6a 12 56 53 e8 ?? ?? ?? ?? c6 85 ?? ?? ff ff 47 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 57 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 77 c6 85 ?? ?? ff ff 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

