rule Trojan_WinNT_Qsbot_A_2147641186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Qsbot.A"
        threat_id = "2147641186"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Qsbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 33 43 66 89 32 43 42 42 66 85 f6 75 f1 8b 47 14 89 41 48 33 c0 89 41 30 89 41 34 89 41 28 89 41 2c}  //weight: 1, accuracy: High
        $x_1_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? a1 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb c6 02 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

