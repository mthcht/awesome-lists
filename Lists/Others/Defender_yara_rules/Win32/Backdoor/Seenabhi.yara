rule Backdoor_Win32_Seenabhi_A_2147688337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Seenabhi.A"
        threat_id = "2147688337"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Seenabhi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a5 a5 66 a5 66 a3 ?? ?? ?? ?? 8d 45 ?? 50 68 ?? ?? ?? ?? a4 c6 45 ?? 53 c6 45 ?? 65 c6 45 ?? 45 c6 45 ?? 6e}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 78 04 83 ff 2a 74 ?? 83 ff 71 74 ?? 81 ff 9a 02 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = "0et3td6an9le" ascii //weight: 1
        $x_1_4 = "0ak3r5ve8t" ascii //weight: 1
        $x_1_5 = "JustTempFun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

