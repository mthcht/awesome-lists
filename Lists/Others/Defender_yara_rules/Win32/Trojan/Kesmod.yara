rule Trojan_Win32_Kesmod_A_2147626292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kesmod.A"
        threat_id = "2147626292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kesmod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 3c 53 56 68 20 00 01 00 68 ?? ?? ?? ?? 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 fc 8d 4d f8 51 6a 04 52 6a 0b ff d6 3d 04 00 00 c0 0f 85 dc 00 00 00 8b 45 f8 50 6a 40 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

