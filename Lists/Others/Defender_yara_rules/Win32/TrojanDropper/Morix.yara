rule TrojanDropper_Win32_Morix_A_2147641103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Morix.A"
        threat_id = "2147641103"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Morix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 08 32 4d f8 8b 55 fc 88 0a 8b 45 f8 83 c0 01 89 45 f8}  //weight: 2, accuracy: High
        $x_1_2 = {5c b3 cc d0 f2 5c c6 f4 b6 af 5c 33 36 30 74 72 61 79 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "lld.dndiw\\s%" ascii //weight: 1
        $x_1_4 = {4e 47 53 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

