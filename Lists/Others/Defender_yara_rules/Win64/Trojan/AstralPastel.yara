rule Trojan_Win64_AstralPastel_A_2147963575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AstralPastel.A"
        threat_id = "2147963575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AstralPastel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 32 36 39 37 33 37 30 32 32 33 61 [0-6] 32 32 36 35 37 32 37 32 36 33 36 66 36 34 36 35 32 32 [0-6] 32 32 36 31 37 32 36 35 36 31 32 32 33 61 [0-6] 32 32 37 35 37 32 36 63 35 66 36 38 36 66 37 33 37 34 35 66 36 64 36 31 37 30 32 32 33 61 32 32}  //weight: 1, accuracy: Low
        $x_1_2 = "26646d6e6368673d" ascii //weight: 1
        $x_1_3 = "636c69656e747665723d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AstralPastel_B_2147963576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AstralPastel.B"
        threat_id = "2147963576"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AstralPastel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Delete Failed!" ascii //weight: 1
        $x_1_2 = "%s%s%%a%d" ascii //weight: 1
        $x_1_3 = {25 73 09 25 73 09 25 73}  //weight: 1, accuracy: High
        $x_1_4 = "%s!%s" ascii //weight: 1
        $x_1_5 = "error1,code: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

