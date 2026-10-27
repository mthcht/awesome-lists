rule Trojan_Win64_BrightOtter_A_2147980981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrightOtter.A"
        threat_id = "2147980981"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrightOtter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 25 30 34 75 2d 25 30 32 75 2d 25 30 32 75 20 25 30 32 75 3a 25 30 32 75 3a 25 30 32 75 5d 20 43 52 41 53 48 20 72 65 61 73 6f 6e 3d 25 73 20 63 6f 64 65 3d 30 78 25 30 38 6c 78 20 61 64 64 72 3d 30 78 25 70 0a}  //weight: 1, accuracy: High
        $x_1_2 = "CRT invalid parameter (line %u)" ascii //weight: 1
        $x_1_3 = "SEH fault code=0x%08lx addr=0x%p" ascii //weight: 1
        $x_1_4 = "heartbeat thread hung" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

