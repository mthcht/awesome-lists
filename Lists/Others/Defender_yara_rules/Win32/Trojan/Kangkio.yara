rule Trojan_Win32_Kangkio_A_2147610897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kangkio.A"
        threat_id = "2147610897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kangkio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\drivers\\KPDrv.sys" ascii //weight: 1
        $x_1_2 = "Mcshield" ascii //weight: 1
        $x_1_3 = "FuAll1" ascii //weight: 1
        $x_3_4 = {68 7a 29 40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 57 8b f9 6a 00 e8 ?? ?? 00 00 83 c4 04 8b cf e8 ?? ?? 00 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00 8b f0 85 f6 74 2f ff 15 ?? ?? 40 00 3d b7 00 00 00 75 22 56 ff 15 48 30 40 00 6a 00 ff 15 34 30 40 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kangkio_C_2147610932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kangkio.C"
        threat_id = "2147610932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kangkio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {bf c9 c4 dc ca c7 d2 f2 ce aa c4 fa b2 bb d3 b5 d3 d0 41 64 6d 69 6e}  //weight: 2, accuracy: High
        $x_1_2 = {4e 4f 44 00 72 61 76 00 6e 6f 64 00 41 6e 74 69 00}  //weight: 1, accuracy: High
        $x_1_3 = "w.kang" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kangkio_D_2147610933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kangkio.D"
        threat_id = "2147610933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kangkio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 36 30 00 ce a2 b5 e3 00}  //weight: 1, accuracy: High
        $x_1_2 = {c8 ce ce f1 b9 dc c0 ed 00}  //weight: 1, accuracy: High
        $x_1_3 = {ce c4 bc fe bc d0 d1 a1 cf ee 00}  //weight: 1, accuracy: High
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
        $x_1_5 = ".kangk.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

