rule Trojan_Win32_Cinject_B_2147619240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinject.B"
        threat_id = "2147619240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "stobject.dll" ascii //weight: 1
        $x_1_2 = "F999333" ascii //weight: 1
        $x_1_3 = {68 c0 d4 01 00 ff 15 ?? ?? ?? ?? 6a 00 6a 02 ff 15 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_4 = {68 ff 00 00 00 6a 42 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ff 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {68 c9 36 00 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 01 01 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

