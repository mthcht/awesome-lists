rule TrojanSpy_Win32_Meseft_2147647657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Meseft"
        threat_id = "2147647657"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Meseft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 10 8a 8b ?? ?? ?? ?? 57 30 0c 06 43 e8 ?? ?? ?? ?? 3b d8 59 72 ?? 8b 44 24 10 50 8a 0c 06 f6 d1 88 0c 06 46}  //weight: 2, accuracy: Low
        $x_1_2 = "browser=%s&site=%s&user=%s&pass=%s" ascii //weight: 1
        $x_1_3 = "POST /gateway/spreaders HTTP/1.0" ascii //weight: 1
        $x_1_4 = "X-Nigger-%c: %u%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

