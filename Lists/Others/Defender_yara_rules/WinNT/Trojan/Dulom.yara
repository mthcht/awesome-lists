rule Trojan_WinNT_Dulom_A_2147653756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Dulom.A"
        threat_id = "2147653756"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Dulom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wxp_x86\\i386\\entrydel.pdb" ascii //weight: 1
        $x_1_2 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\Device\\HarddiskVolume1\\Program Files" wide //weight: 1
        $x_1_4 = "Arquivos de programas\\drivers\\gbpkm." wide //weight: 1
        $x_1_5 = {83 7d 0c 00 75 ?? 83 7d 18 00 74 ?? 8b 4d 14 0f b7 11 85 d2 74 ?? c7 45 f8 05 00 00 80 8b 45 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_WinNT_Dulom_B_2147653757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Dulom.B"
        threat_id = "2147653757"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Dulom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wxp_x86\\i386\\entry.pdb" ascii //weight: 1
        $x_1_2 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "GbpKm" wide //weight: 1
        $x_1_4 = "GbpSv" wide //weight: 1
        $x_1_5 = {89 45 e0 c7 45 e4 ?? ?? ?? ?? c7 45 b4 ?? ?? ?? ?? 6a 1e 8d 4d b8 51 6a 01 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? ?? ?? 89 45 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

