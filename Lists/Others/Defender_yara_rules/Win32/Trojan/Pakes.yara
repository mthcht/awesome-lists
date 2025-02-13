rule Trojan_Win32_Pakes_I_2147617480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pakes.gen!I"
        threat_id = "2147617480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pakes"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 81 c2 00 0e 00 00 6a 00 c1 e2 04 52 56 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4c 04 08 80 f1 ?? 88 4c 04 08 40 83 f8 10 7c ef}  //weight: 1, accuracy: Low
        $x_5_3 = {8b 54 24 14 8b ce 8d 44 1a c1 50 8d 46 04 50 e8 ?? 00 00 00 83 c3 40 83 c5 40 3b df 72 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pakes_I_2147619552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pakes.I"
        threat_id = "2147619552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pakes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KfLowerIrql" ascii //weight: 1
        $x_1_2 = "KeGetCurrentIrql" ascii //weight: 1
        $x_1_3 = "ZwQueryDirectoryFile" ascii //weight: 1
        $x_1_4 = "ZwCreateFile" ascii //weight: 1
        $x_1_5 = "ZwEnumerateKey" ascii //weight: 1
        $x_1_6 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_7 = {55 8b ec 51 56 8b 35 ?? ?? 01 00 ff d6 ff d6 3a c3 73 0d 8a cb ff 15 ?? ?? 01 00 88 ?? ?? eb 0d ff d6 8a cb 88 ?? ?? ff 15 ?? ?? 01 00 8a ?? ?? 5e}  //weight: 1, accuracy: Low
        $x_1_8 = {0f 20 c0 8b d8 81 e3 ff ff fe ff 0f 22 c3}  //weight: 1, accuracy: High
        $x_1_9 = {56 8b 34 81 80 3e e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

