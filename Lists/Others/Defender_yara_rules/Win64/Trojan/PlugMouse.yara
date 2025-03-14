rule Trojan_Win64_PlugMouse_A_2147936011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PlugMouse.A!dha"
        threat_id = "2147936011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PlugMouse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "//sosano.jpg" ascii //weight: 3
        $x_1_2 = "Decata." ascii //weight: 1
        $x_1_3 = "Invture!" ascii //weight: 1
        $x_1_4 = "ghsdfsdfghhu!" ascii //weight: 1
        $x_1_5 = "Fggsdsssssbcess!" ascii //weight: 1
        $x_1_6 = "in tadddrgled!" ascii //weight: 1
        $x_1_7 = "rdddds!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

