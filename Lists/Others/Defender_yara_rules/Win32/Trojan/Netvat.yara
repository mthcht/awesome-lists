rule Trojan_Win32_Netvat_C_2147654508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netvat.C"
        threat_id = "2147654508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netvat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {39 75 10 7c 1a 8b 45 08 8d 0c 06 8b c6 99 f7 7d 14 8b 45 0c 8a 04 02 30 01 46 3b 75 10 7e e6}  //weight: 4, accuracy: High
        $x_2_2 = "SurrendHome" ascii //weight: 2
        $x_2_3 = "Avt-Net" ascii //weight: 2
        $x_2_4 = "X2trZzEkJGJaaGhWXFppJW9eWGclZVprMS4u9w==" ascii //weight: 2
        $x_1_5 = "%s\\360rpv.exe" ascii //weight: 1
        $x_1_6 = "svcnet32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Netvat_E_2147657974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netvat.E"
        threat_id = "2147657974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netvat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Avt-Net" ascii //weight: 1
        $x_1_2 = "Com Infrastructure" ascii //weight: 1
        $x_1_3 = "%s\\vvpvs.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netvat_E_2147657975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netvat.E!Dll"
        threat_id = "2147657975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netvat"
        severity = "Critical"
        info = "Dll: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 75 5f 68 6f 6f 6b 00 25 73 25 73 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "ivus8.*oaprcdap/{jbr/kgp98" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

