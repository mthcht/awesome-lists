rule Worm_Win32_Rombrast_A_2147657927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rombrast.gen!A"
        threat_id = "2147657927"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rombrast"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 10 8d 74 71 08 bb 00 30 00 00 66 85 1e 74 ?? 0f b7 36 8b 19 81 e6 ff 0f 00 00 03 75 08 (03 f3|01) ff 45 10 39 7d 10}  //weight: 2, accuracy: Low
        $x_1_2 = "ERROR_BRAIN_TOO_SMALL" ascii //weight: 1
        $x_1_3 = "Windows Death" ascii //weight: 1
        $x_1_4 = "data=%s<|>%s<|>%d<|>%d<|>%s<|>%d" ascii //weight: 1
        $x_1_5 = "data=USB<|>Infected Drive %c:\\<||>" ascii //weight: 1
        $x_1_6 = "?act=spreading&ver=%s" ascii //weight: 1
        $x_1_7 = {7b 00 61 00 35 00 64 00 63 00 62 00 66 00 31 00 30 00 2d 00 36 00 35 00 33 00 30 00 2d 00 31 00 31 00 64 00 32 00 2d 00 39 00 30 00 31 00 66 00 2d 00 30 00 30 00 63 00 30 00 34 00 66 00 62 00 39 00 35 00 31 00 65 00 64 00 7d 00 00 00 00 00 2e 00 45 00 58 00 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

