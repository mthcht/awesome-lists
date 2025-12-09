rule Trojan_MSIL_VanillaRat_CXJK_2147849512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VanillaRat.CXJK!MTB"
        threat_id = "2147849512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VanillaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Debug\\VanillaRat.pdb" ascii //weight: 1
        $x_1_2 = "Remote Shell" wide //weight: 1
        $x_1_3 = "Password Viewer" wide //weight: 1
        $x_1_4 = "Audio Recorder" wide //weight: 1
        $x_1_5 = "Keylogger" wide //weight: 1
        $x_1_6 = "Remote Desktop Viewer" wide //weight: 1
        $x_1_7 = "btnRestartShell" wide //weight: 1
        $x_1_8 = "VanillaRat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VanillaRat_ANJB_2147956596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VanillaRat.ANJB!MTB"
        threat_id = "2147956596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VanillaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0c 2b 53 07 08 6f ?? 00 00 0a 0d 09 28 ?? 00 00 0a 2c 37 09 28 ?? 00 00 0a 2d 12 09 1f 61 59 03 59 1f 1a 58 1f 1a 5d 1f 61 58 d1 2b 10 09 1f 41 59 03 59 1f 1a 58 1f 1a 5d 1f 41 58 d1 13 04 06 11 04 6f ?? 00 00 0a 26 2b 08 06 09 6f ?? 00 00 0a 26 08 17 58 0c 08 07 6f ?? 00 00 0a 32 a4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VanillaRat_LM_2147959068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VanillaRat.LM!MTB"
        threat_id = "2147959068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VanillaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {00 28 42 00 00 0a 7e 1c 00 00 04 17 28 4e 00 00 0a 00 7e 1c 00 00 04 28 4f 00 00 0a 26 16 28 49 00 00 0a 00 00 2b 5e 00 7e 24 00 00 04 72 e4 03 00 70 28 1e 00 00 0a 13 04 11 04 2c 47 00 7e 50 00 00 0a 72 ee 03 00 70 17 6f 51 00 00 0a 13 05}  //weight: 20, accuracy: High
        $x_10_2 = {26 00 00 de 00 00 00 11 05 72 4a 04 00 70 28 42 00 00 0a 6f 53 00 00 0a 00 00 de 05}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

