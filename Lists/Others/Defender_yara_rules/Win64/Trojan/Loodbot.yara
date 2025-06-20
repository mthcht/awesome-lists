rule Trojan_Win64_Loodbot_A_2147944217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Loodbot.A"
        threat_id = "2147944217"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Loodbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "+v$x+v$xv$+xv+$xv$+x+$vx+$vx$v+x+$vx$+vx+v" ascii //weight: 2
        $x_1_2 = {76 32 2e 30 2e 35 30 37 32 37 00 00 00 00 00 00 76 34 2e 30 2e 33 30 33 31 39 00 00 00 00 00 00 53 79 73 74 65 6d 41 70 70}  //weight: 1, accuracy: High
        $x_1_3 = "\\\\AppData\\\\Roaming\\\\Gapic\\\\" ascii //weight: 1
        $x_2_4 = {49 8b cd 48 83 f8 15 48 0f 45 c8 42 0f b6 04 31 30 02 48 8d 41 01 48 8d 52 01 49 83 e8 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

