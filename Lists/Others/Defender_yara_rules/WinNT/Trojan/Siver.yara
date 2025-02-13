rule Trojan_WinNT_Siver_A_2147629567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Siver.A"
        threat_id = "2147629567"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Siver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 0f 20 c0 a3 ?? ?? ?? ?? 25 ff ff fe ff 0f 22 c0 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d 1c 03 00 12 00 74 ?? 8b 45 f8 e9 ?? ?? ?? ?? 83 7d f8 00 0f 8c ?? ?? ?? ?? c7 45 c8 00 04 00 00 c7 45 cc 00 00 00 00 c7 45 d0 00 02 00 00 c7 45 d4 00 01 00 00 c7 45 d8 01 01 00 00 b9 05 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

