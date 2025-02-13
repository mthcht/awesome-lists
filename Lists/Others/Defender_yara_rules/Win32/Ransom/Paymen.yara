rule Ransom_Win32_Paymen_PA_2147755069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paymen.PA!MTB"
        threat_id = "2147755069"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paymen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 0f ?? ?? ?? ?? ?? 8b 4d f8 8a 54 [0-4] 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 03 55 f8 88 55 ff 0f b6 45 ff 35 a7 00 00 00 88 45 ff 0f b6 4d ff 81 c1 e3 00 00 00 88 4d ff}  //weight: 1, accuracy: Low
        $x_1_2 = {88 45 ff 0f b6 4d ff 03 4d f8 88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff 05 ec 00 00 00 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 03 55 f8 88 55 ff 8b 45 f8 8a 4d ff 88 4c ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = "Dear user! Your computer is encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

