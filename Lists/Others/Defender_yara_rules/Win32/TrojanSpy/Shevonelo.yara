rule TrojanSpy_Win32_Shevonelo_STA_2147776235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Shevonelo.STA"
        threat_id = "2147776235"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Shevonelo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 0f 46 88 0a 42 8a 0e 84 c9 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {81 ec 80 00 00 00 f3 a5 6a 20 59 8b fc 8d 75 08 f3 a5}  //weight: 1, accuracy: High
        $x_1_3 = {33 c9 c7 40 40 ?? ?? ?? ?? 89 48 64 89 48 60 89 48 68 c7 40 44 ?? ?? ?? ?? c7 40 48 ?? ?? ?? ?? c7 40 4c ?? ?? ?? ?? c7 40 50 ?? ?? ?? ?? c7 40 54}  //weight: 1, accuracy: Low
        $x_1_4 = {68 a3 da b7 88 e8}  //weight: 1, accuracy: High
        $x_1_5 = {68 53 c1 1f 2e e8}  //weight: 1, accuracy: High
        $x_1_6 = {68 9a 34 63 bc e8}  //weight: 1, accuracy: High
        $x_1_7 = {68 9d ec 5a 86 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

