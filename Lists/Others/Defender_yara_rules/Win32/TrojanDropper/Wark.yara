rule TrojanDropper_Win32_Wark_A_2147632430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Wark.A"
        threat_id = "2147632430"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Wark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0c b8 68 00 00 00 eb 05 b8 66 00 00 00 8d 8d ?? fc ff ff 51 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {76 16 8d 4c ?? ?? e8 ?? ?? 00 00 8a 14 2e 32 d0 88 14 2e 46 3b f3 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

