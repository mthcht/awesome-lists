rule Trojan_Win64_StuckintheMiddle_A_2147832581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StuckintheMiddle.A!dha"
        threat_id = "2147832581"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StuckintheMiddle"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U9ELetx8eMR8pd5koFamoOyuf9tTRTPG" ascii //weight: 1
        $x_1_2 = "EtwEventWrite" ascii //weight: 1
        $x_1_3 = "license" ascii //weight: 1
        $x_1_4 = {b8 e1 83 0f 3e 41 f7 e3 c1 ea 03 6b c2 21 2b c8 41 0f b6 c0 0f b6 0c 39 03 c8 b8 e1 83 0f 3e f7 e1 c1 ea 03 6b c2 21 2b c8 b8 e1 83 0f 3e 41 f7 e2 44 0f b6 04 39 41 8b ca c1 ea 03 41 ff c2 6b c2 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

