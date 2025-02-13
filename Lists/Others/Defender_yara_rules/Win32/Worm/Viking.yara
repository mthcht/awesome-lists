rule Worm_Win32_Viking_NA_2147625601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Viking.NA"
        threat_id = "2147625601"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2e 62 73 00 8b 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 85 ?? ?? ff ff ff 70 38 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 e8 ?? ?? ff ff}  //weight: 3, accuracy: Low
        $x_1_2 = {00 65 78 65 00 [0-16] 68 74 6d [0-16] 68 74 6d 6c [0-16] 61 73 70 [0-16] 61 73 70 78 [0-16] 72 61 72}  //weight: 1, accuracy: Low
        $x_1_3 = "GET %s?name=%s HTTP/1.1" ascii //weight: 1
        $x_1_4 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 4f 50 45 4e 3d 25 73 5c 25 73 0d 0a 73 68 65 6c 6c 5c 6f 70 65 6e 3d [0-18] 73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 25 73 5c 25 73 20 25 73 0d 0a 73 68 65 6c 6c 5c 6f 70 65 6e 5c 44 65 66 61 75 6c 74 3d}  //weight: 1, accuracy: Low
        $x_1_5 = "MSN Gaming Zone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

