rule Trojan_Win64_Claretore_A_2147658719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Claretore.A"
        threat_id = "2147658719"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Claretore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 48 c1 e2 20 4c 8d 05 ?? ?? ?? ?? 48 0b c2 ba 04 01 00 00 4c 8b c8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "$mid=%S&uid=%d&version=%s$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Claretore_B_2147680215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Claretore.B"
        threat_id = "2147680215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Claretore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 28 01 23 45 67 c7 44 24 2c 89 ab cd ef c7 44 24 30 fe dc ba 98 c7 44 24 34 76 54 32 10}  //weight: 1, accuracy: High
        $x_1_2 = "wv=%s&uid=%d&lng=%s&mid=%s&res=%s&v=%08X" ascii //weight: 1
        $x_1_3 = "$mid=%S&uid=%d&version=%s$" ascii //weight: 1
        $x_1_4 = "C:\\Project\\UM\\branches\\username\\bin\\[Release.x64]Clicker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

