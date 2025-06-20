rule Trojan_Win64_StealerBot_A_2147944218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealerBot.A"
        threat_id = "2147944218"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealerBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "StealerBot." ascii //weight: 2
        $x_1_2 = {2e 64 6c 6c 00 49 63 65 43 72 65 61 6d}  //weight: 1, accuracy: High
        $x_1_3 = "DEFENSTRATION" ascii //weight: 1
        $x_1_4 = {2f 49 53 50 52 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3f 64 61 74 61 3d}  //weight: 1, accuracy: Low
        $x_1_5 = "TEZUV0JVVExe" ascii //weight: 1
        $x_1_6 = "UE5JT1NTVwlDS0s=" ascii //weight: 1
        $x_1_7 = "U1VCSUM=" ascii //weight: 1
        $x_1_8 = {33 d2 b9 e9 fd 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_9 = {48 ff c1 48 3b 09 00 80 34 08}  //weight: 1, accuracy: Low
        $x_1_10 = {b9 50 00 00 00 [0-6] 48 8b 05 ?? ?? ?? ?? 80 78 04 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

