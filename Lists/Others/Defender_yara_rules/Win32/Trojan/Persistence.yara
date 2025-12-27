rule Trojan_Win32_Persistence_LocalAccount_2147950573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Persistence.LocalAccount.Group.Add.C"
        threat_id = "2147950573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Persistence"
        severity = "Critical"
        info = "Group: an internal category used to refer to some threats"
        info = "Add: an internal category used to refer to some threats"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "net" wide //weight: 10
        $x_10_2 = "localgroup" wide //weight: 10
        $x_1_3 = "power users" wide //weight: 1
        $x_1_4 = "remote desktop users" wide //weight: 1
        $x_10_5 = "sbusername" wide //weight: 10
        $x_10_6 = "/add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Persistence_Registry_2147955108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Persistence.Registry.TimeProvider.B"
        threat_id = "2147955108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Persistence"
        severity = "Critical"
        info = "TimeProvider: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " import " wide //weight: 1
        $x_1_2 = "sb_" wide //weight: 1
        $x_1_3 = "sbreg.reg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

