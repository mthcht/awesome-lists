rule Trojan_Win32_Losmion_A_2147685270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Losmion.A"
        threat_id = "2147685270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Losmion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 50 03 55 57 bd 80 80 80 80 8b 38 83 c0 04 8d 8f ff fe fe fe f7 d7 21 f9 21 e9 75 ?? 8b 38 83 c0 04 8d 8f ff fe fe fe}  //weight: 1, accuracy: Low
        $x_1_2 = "Reg Add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run\" /ve /t REG_SZ /d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

