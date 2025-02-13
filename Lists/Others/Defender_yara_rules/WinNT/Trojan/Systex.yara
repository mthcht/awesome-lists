rule Trojan_WinNT_Systex_A_2147662102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Systex.A"
        threat_id = "2147662102"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Systex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c 60 b9 76 01 00 00 0f 32 a3 ?? ?? ?? ?? 61 9d 83 3d ?? ?? ?? ?? 06 73 ?? bb ?? ?? ?? ?? c7 45 fc 09 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 02 75 ?? c7 05 ?? ?? ?? ?? 21 02 00 00 c3 83 f8 01 75 0b c7 05 ?? ?? ?? ?? 25 02 00 00 c3 85 c0 75 33 c7 05 ?? ?? ?? ?? 12 02 00 00 c3 83 f8 06}  //weight: 1, accuracy: Low
        $x_1_3 = "SOGOUEXPLORER.EXE" ascii //weight: 1
        $x_1_4 = "GREENBROWSER.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Systex_B_2147679150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Systex.B"
        threat_id = "2147679150"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Systex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 04 0f 82 84 00 00 00 81 3e 48 54 54 50 0f 85 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 5c 2e 5c 50 65 72 73 69 73 74 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 41 46 45 43 45 4e 54 45 52 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 74 2e 61 73 70 3f 6f 73 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 74 61 72 74 70 61 67 65 6e 75 6d 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 6e 74 69 5f 66 69 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

