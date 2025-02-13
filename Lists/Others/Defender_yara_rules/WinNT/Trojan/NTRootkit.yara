rule Trojan_WinNT_NTRootkit_H_2147618156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/NTRootkit.H"
        threat_id = "2147618156"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "NTRootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 74 65 6d 00 56 57 ff 15 ?? ?? ?? ?? 8b f8 33 f6 6a 06 8d 04 3e 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 74 0e 46 81 fe 00 30 00 00 7c df 33 c0 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {fa 8b 49 01 8b 1d ?? ?? ?? ?? b8 ?? ?? ?? ?? 8d 0c 8b 87 01 a3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4f 01 b8 ?? ?? ?? ?? 8d 0c 8a 87 01 a3 ?? ?? ?? ?? fb}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Registry\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

