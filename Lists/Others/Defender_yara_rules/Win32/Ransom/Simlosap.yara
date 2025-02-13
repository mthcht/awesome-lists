rule Ransom_Win32_Simlosap_A_2147695417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Simlosap.A"
        threat_id = "2147695417"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Simlosap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 24 8d 45 ?? 33 d2 8a d3 83 c2 41 e8 ?? ?? ?? ?? 8d 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 43 80 fb 1a 75 89}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 05 00 00 00 e8 ?? ?? ?? ?? b8 1a 00 00 00 e8 ?? ?? ?? ?? 8b d0 80 c2 41 8d 85 ?? ?? ff ff e8 ?? ?? ?? ?? 8b 95 ?? ?? ff ff 8d 45 fc e8 ?? ?? ?? ?? 4b 75 d0}  //weight: 1, accuracy: Low
        $x_1_3 = "accdb:abf:a3d:asm:fbx:fbw:fbk:fdb:fbf:max:m3d:ldf:keystore" ascii //weight: 1
        $x_1_4 = {61 73 69 6d 63 6c 6f 73 65 70 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 72 69 7a 72 61 6b 7b 7d 7b 7d 7b 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

