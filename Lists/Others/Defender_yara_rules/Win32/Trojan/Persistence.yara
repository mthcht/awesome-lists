rule Trojan_Win32_Persistence_LocalAccount_2147949451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Persistence.LocalAccount.Group.Add.AV.A"
        threat_id = "2147949451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Persistence"
        severity = "Critical"
        info = "Group: an internal category used to refer to some threats"
        info = "Add: an internal category used to refer to some threats"
        info = "AV: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net" wide //weight: 1
        $x_1_2 = " localgroup" wide //weight: 1
        $x_1_3 = "power users" wide //weight: 1
        $x_1_4 = "sbusername" wide //weight: 1
        $x_1_5 = "/add" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Persistence_LocalAccount_2147949452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Persistence.LocalAccount.Group.Add.AV.B"
        threat_id = "2147949452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Persistence"
        severity = "Critical"
        info = "Group: an internal category used to refer to some threats"
        info = "Add: an internal category used to refer to some threats"
        info = "AV: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net" wide //weight: 1
        $x_1_2 = " localgroup" wide //weight: 1
        $x_1_3 = "remote desktop users" wide //weight: 1
        $x_1_4 = "sbusername" wide //weight: 1
        $x_1_5 = "/add" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

