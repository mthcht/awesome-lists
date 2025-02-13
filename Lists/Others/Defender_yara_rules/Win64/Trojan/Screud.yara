rule Trojan_Win64_Screud_A_2147678401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Screud.A"
        threat_id = "2147678401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Screud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 bb 00 80 c1 2a 21 4e 62 fe 49 03 cb 48 b8 bd 42 7a e5 d5 94 bf d6 48 f7 e1 48 83 c8 ff 48 c1 ea 17 48 81 fa 7f d2 ff 7f 48 0f 4f d0}  //weight: 1, accuracy: High
        $x_1_2 = "EnableEUDC" ascii //weight: 1
        $x_1_3 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide //weight: 1
        $x_1_4 = "\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

