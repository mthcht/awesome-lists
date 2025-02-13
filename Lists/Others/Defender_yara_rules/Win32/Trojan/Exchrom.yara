rule Trojan_Win32_Exchrom_B_2147692982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Exchrom.B"
        threat_id = "2147692982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Exchrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {80 c2 0f f6 d2 fe ca f6 d2 2a d0 80 ea 25 f6 d2 80 ea 1d 80 f2 e8 80 ea 06 80 f2 aa f6 d2 02 d0 f6 d2 32 d0 80 f2 eb}  //weight: 5, accuracy: High
        $x_4_2 = {68 f4 01 00 00 ff d3 6a 00 be ?? ?? ?? 00 e8 ?? ?? ff ff 83 c4 04 68 e0 2e 00 00 ff d3}  //weight: 4, accuracy: Low
        $x_2_3 = "http://%s/cpp/state" ascii //weight: 2
        $x_2_4 = "http://%s/cpp/app.crx" ascii //weight: 2
        $x_1_5 = "filmpika.com" ascii //weight: 1
        $x_1_6 = "ketant.net" ascii //weight: 1
        $x_1_7 = "bakstoran.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

