rule Trojan_MSIL_Growtopia_ATR_2147779930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.ATR!MTB"
        threat_id = "2147779930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 2b 13 07 08 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 58 6f ?? ?? ?? 0a 0b 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 25 0c 15 33 dd}  //weight: 10, accuracy: Low
        $x_5_2 = "https:\\\\\\/\\\\\\/i.ibb.co\\\\\\/[A-z0-9]+\\/[A-z0-9]+.jpg" ascii //weight: 5
        $x_4_3 = "DisableTaskMgr" ascii //weight: 4
        $x_4_4 = "SOFTWARE\\Growtopia" ascii //weight: 4
        $x_4_5 = "Discord" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Growtopia_LF_2147783782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.LF!MTB"
        threat_id = "2147783782"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 14 fe 01 0d 09 2c 05 14 13 04 2b 47 03 14 fe 01 13 05 11 05 2c 07 7e 11 00 00 0a 10 01 02 28 17 00 00 0a 0a 28 12 00 00 0a 03 6f 13 00 00 0a 0b 28 14 00 00 0a 07 6f 15 00 00 0a 0b 06 07 28 04 00 00 06 0c 28 12 00 00 0a 08 6f 18 00 00 0a 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: High
        $x_1_2 = {00 28 2c 00 00 0a 00 16 28 2d 00 00 0a 00 00 28 06 00 00 06 00 72 01 00 00 70 72 33 00 00 70 28 02 00 00 06 72 3f 00 00 70 72 33 00 00 70 28 02 00 00 06 16 1f 10 28 2e 00 00 0a 26 00 de 05 26 00 00 de 00 2a}  //weight: 1, accuracy: High
        $x_1_3 = "GrowtopiaTrainer" ascii //weight: 1
        $x_1_4 = "smtp.gmail.com" ascii //weight: 1
        $x_1_5 = "Save.dat not found" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Growtopia_RJ_2147838421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.RJ!MTB"
        threat_id = "2147838421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 14 fe 03 0c 08 2c 31 00 00 07 0d 16 13 04 2b 1c 09 11 04 9a 13 05 00 06 11 05 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 00 11 04 17 58 13 04 11 04 09 8e 69 32 dd}  //weight: 1, accuracy: Low
        $x_1_2 = "Growtopia" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Growtopia_PSUJ_2147852525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.PSUJ!MTB"
        threat_id = "2147852525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 0a 26 72 15 00 00 70 73 0f 00 00 0a 0a 06 72 33 00 00 70 6f ?? 00 00 0a 00 06 72 4a 0a 00 70 6f ?? 00 00 0a 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Growtopia_PAT_2147888530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.PAT!MTB"
        threat_id = "2147888530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Growtopia-Full-Fud-Stealer-master\\obj\\Debug\\Fud.pdb" ascii //weight: 1
        $x_1_2 = "discord.com/api/webhooks/1007285810468507658/g4q5Mp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Growtopia_ADF_2147896065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.ADF!MTB"
        threat_id = "2147896065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0d 06 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 04 09 11 04 11 04 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 58 6f ?? ?? ?? 0a 17 8d ?? ?? ?? 01 13 06 11 06 16 1f 20 9d 11 06 6f ?? ?? ?? 0a 19 9a 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 25 2d 06 26 72 ?? ?? ?? 70 13 05 de 0a}  //weight: 10, accuracy: Low
        $x_5_2 = "Software\\Growtopia" ascii //weight: 5
        $x_5_3 = "tankid_password" ascii //weight: 5
        $x_4_4 = "\\pass.txt" ascii //weight: 4
        $x_4_5 = "select * from Win32_OperatingSystem" ascii //weight: 4
        $x_4_6 = "ipv4bot" ascii //weight: 4
        $x_3_7 = "discordapp" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Growtopia_PTCE_2147896859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.PTCE!MTB"
        threat_id = "2147896859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 19 00 00 70 a2 25 19 08 6f 02 00 00 06 a2 25 1a 72 31 00 00 70 a2 28 ?? 00 00 0a 6f 1e 00 00 0a 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Growtopia_PAAB_2147899474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.PAAB!MTB"
        threat_id = "2147899474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 06 08 91 72 b8 08 00 70 08 72 b8 08 00 70 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 13 06 11 06 2d d0}  //weight: 1, accuracy: Low
        $x_1_2 = "MALWARE" wide //weight: 1
        $x_1_3 = "VIRUS" wide //weight: 1
        $x_1_4 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide //weight: 1
        $x_1_5 = "C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Growtopia_ARA_2147936698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growtopia.ARA!MTB"
        threat_id = "2147936698"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 06 08 91 72 ?? ?? ?? 70 08 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 13 06 11 06 2d d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

