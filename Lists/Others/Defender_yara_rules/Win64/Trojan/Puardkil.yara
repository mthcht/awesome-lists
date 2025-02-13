rule Trojan_Win64_Puardkil_A_2147734322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Puardkil.A"
        threat_id = "2147734322"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Puardkil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 89 08 01 00 00 48 8b 40 18 48 33 c1}  //weight: 1, accuracy: High
        $x_1_2 = "Path - PatchGuard context entrypoint not found" ascii //weight: 1
        $x_1_3 = "b9 01 00 00 00 44 0f 22 c1 48 8b 14 24 48 8b 4c 24 08" ascii //weight: 1
        $x_1_4 = "48 8D 05 ?? ?? ?? ?? ?? 89 ?? 08 01 00 00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

