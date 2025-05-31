rule Trojan_MSIL_Clipbanker_RAA_2147760780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.RAA!MTB"
        threat_id = "2147760780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_2 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "BitConverter" ascii //weight: 1
        $x_1_5 = "file:///" wide //weight: 1
        $x_1_6 = "UNNAM3D___CLIPPER" ascii //weight: 1
        $x_1_7 = "add_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipbanker_NBA_2147838856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.NBA!MTB"
        threat_id = "2147838856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 02 7b 39 00 00 04 1e 62 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a d2 60 7d ?? ?? ?? 04 06 17 58 0a 06 1b 3f ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "/create /sc MINUTE /mo 3 /tn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipbanker_NCB_2147843462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.NCB!MTB"
        threat_id = "2147843462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 72 bd 07 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 06 6f ?? ?? 00 0a 25 07 6f ?? ?? 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "RoobetCrash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipbanker_NCB_2147843462_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.NCB!MTB"
        threat_id = "2147843462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 13 00 fe ?? ?? 00 5c fe ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 58 fe ?? ?? 00 5a fe ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 16 40 ?? ?? ?? 00 fe ?? ?? 00 17 59 fe ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "sssc.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipbanker_AMAB_2147890315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.AMAB!MTB"
        threat_id = "2147890315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetText" ascii //weight: 1
        $x_1_2 = "SetText" ascii //weight: 1
        $x_1_3 = "Clipboard" ascii //weight: 1
        $x_1_4 = "SetClipboardViewer" ascii //weight: 1
        $x_1_5 = "YANDEX_MONEY" ascii //weight: 1
        $x_1_6 = "STEAMTRADE_LINK" ascii //weight: 1
        $x_1_7 = "ETHEREUM" ascii //weight: 1
        $x_1_8 = "https://steamcommunity.com/tradeoffer/new/?partner" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_10 = "0x5a87F00A1dac28a285C7D336a1b29Fdc57b34115" ascii //weight: 1
        $x_1_11 = "t1QfsrzscKgf5KiabUcAJYZbTcju2dTriw5" ascii //weight: 1
        $x_1_12 = "^41001[0-9]?[\\d\\- ]{7,11}$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipbanker_SPBN_2147909806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.SPBN!MTB"
        threat_id = "2147909806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 07 03 6f ?? ?? ?? 0a 07 04 6f ?? ?? ?? 0a 73 e3 00 00 0a 0c 07 6f ?? ?? ?? 0a 0d 08 09 17 73 e5 00 00 0a 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipbanker_KAE_2147913974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.KAE!MTB"
        threat_id = "2147913974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 03 00 fe 0c 04 00 6f ?? 00 00 0a fe 0e 05 00 00 fe 0c 01 00 fe 0c 05 00 fe 0c 00 00 fe 0c 02 00 25 20 01 00 00 00 58 fe 0e 02 00 6f ?? 00 00 0a 61 d2 6f ?? 00 00 0a 00 fe 0c 02 00 fe 0c 00 00 6f ?? 00 00 0a 5d fe 0e 02 00 00 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00 fe 0c 04 00 fe 0c 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipbanker_NITA_2147942582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipbanker.NITA!MTB"
        threat_id = "2147942582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 3f 12 00 28 ?? 00 00 0a 0b 02 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 28 28 ?? 00 00 0a 7e 06 00 00 04 7e 08 00 00 04 12 01 28 ?? 00 00 0a 6f 52 00 00 0a 28 ?? 00 00 06 6f 53 00 00 0a 0c de 1b 12 00 28 ?? 00 00 0a 2d b8}  //weight: 2, accuracy: Low
        $x_2_2 = {72 97 05 00 70 0a 28 ?? 00 00 0a 0b 07 06 28 ?? 00 00 0a 2c 18 07 0a 07 28 ?? 00 00 06 0c 08 07 28 ?? 00 00 0a 2c 06 08 28 ?? 00 00 0a 20 58 02 00 00 28 ?? 00 00 0a 2b cd}  //weight: 2, accuracy: Low
        $x_1_3 = "SendToTelegram" ascii //weight: 1
        $x_1_4 = "DecryptData" ascii //weight: 1
        $x_1_5 = "Keylogger started" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

