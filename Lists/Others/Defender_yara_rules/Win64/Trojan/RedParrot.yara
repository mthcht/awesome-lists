rule Trojan_Win64_RedParrot_HC_2147946103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedParrot.HC"
        threat_id = "2147946103"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedParrot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "code heap analysis" ascii //weight: 1
        $x_1_2 = "[MachCode]" ascii //weight: 1
        $x_1_3 = "KeySize" ascii //weight: 1
        $x_1_4 = "ModulusSize" ascii //weight: 1
        $x_2_5 = {32 00 30 00 32 00 35 00 30 00 35 00 30 00 37 00 2d 00 32 00 33 00 30 00 30 00 30 00 ?? ?? 2e 00 6c 00 6f 00 67 00}  //weight: 2, accuracy: Low
        $x_2_6 = "Splunk941Install_" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_RedParrot_A_2147946139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedParrot.A!dha"
        threat_id = "2147946139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedParrot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Splunk941Install_" wide //weight: 1
        $x_1_2 = {32 00 30 00 32 00 35 00 30 00 35 00 30 00 37 00 2d 00 32 00 33 00 30 00 30 00 30 00 ?? ?? 2e 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_RedParrot_B_2147946140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedParrot.B!dha"
        threat_id = "2147946140"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedParrot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OpenJDK 64-Bit Minimal VM" ascii //weight: 1
        $x_1_2 = ": this object cannot use a null IV" ascii //weight: 1
        $x_1_3 = {43 00 3a 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-128] 2e 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

