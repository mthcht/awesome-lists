rule Trojan_Win64_SuoMi_A_2147981808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SuoMi.A"
        threat_id = "2147981808"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SuoMi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 09 13 11 15 03 1d 1b 19 12 08}  //weight: 1, accuracy: High
        $x_1_2 = ">.3+/9.r.9(" ascii //weight: 1
        $x_1_3 = "*?051;oklr>,0" ascii //weight: 1
        $x_1_4 = {76 63 6c 69 6d 67 33 37 30 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SuoMi_B_2147981815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SuoMi.B"
        threat_id = "2147981815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SuoMi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/loader/src/task.rs" ascii //weight: 1
        $x_1_2 = "/platform/src/worm.rs" ascii //weight: 1
        $x_1_3 = "/platform/src/persist/plant.rs" ascii //weight: 1
        $x_1_4 = "/supervisor/src/ops/screenshot.rs" ascii //weight: 1
        $x_1_5 = "/supervisor/src/ops/shell.rs" ascii //weight: 1
        $x_1_6 = "/transport/src/proxy.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

