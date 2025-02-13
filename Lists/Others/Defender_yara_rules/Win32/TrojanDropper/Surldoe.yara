rule TrojanDropper_Win32_Surldoe_A_2147621055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Surldoe.gen!A"
        threat_id = "2147621055"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Surldoe"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 a1 ?? ?? 40 00 8b 00 ff d0 68 05 01 00 00 a1 ?? ?? 40 00 50 a1 ?? ?? 40 00 8b 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d7 8b 4d fc 02 54 19 ff 88 54 18 ff 43 4e 75 e7}  //weight: 1, accuracy: High
        $x_1_3 = {8a 54 1a ff 80 ea ?? 88 54 18 ff 43 4e 75}  //weight: 1, accuracy: Low
        $x_1_4 = {00 75 73 65 00 ff ff ff ff 02 00 00 00 72 33 00}  //weight: 1, accuracy: High
        $n_20_5 = "http://www.exejoiner.com" wide //weight: -20
        $n_20_6 = "\\\\.\\SMARTVSD" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

