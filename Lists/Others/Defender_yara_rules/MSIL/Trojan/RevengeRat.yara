rule Trojan_MSIL_RevengeRat_JIY_2147817413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.JIY!MTB"
        threat_id = "2147817413"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 25 00 00 0a 0a 06 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 29 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 00 08 18 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_NUQ_2147824709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.NUQ!MTB"
        threat_id = "2147824709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 05 03 11 05 91 06 61 09 08 91 61 b4 9c 08 04 6f ?? ?? ?? 0a 17 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_RVT_2147826854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.RVT!MTB"
        threat_id = "2147826854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d6 03 8e 69 11 04 16 9a 6f ?? ?? ?? 0a 04 6f ?? ?? ?? 0a d6 da 6f ?? ?? ?? 0a 00 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_REAV_2147827959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.REAV!MTB"
        threat_id = "2147827959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 fe 01 13 07 11 07 2c 02 17 0d 03 09 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 02 11 06 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 07 08 d8 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 09 17 d6 0d 11 06 17 d6 13 06 11 06 11 05 31 b1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_REVV_2147827960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.REVV!MTB"
        threat_id = "2147827960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 91 13 05 00 07 06 11 05 20 78 0a e3 05 58 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 09 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ART_2147841221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ART!MTB"
        threat_id = "2147841221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 06 13 05 2b 28 07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f 2e 00 00 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 06 31 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ART_2147841221_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ART!MTB"
        threat_id = "2147841221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0b 07 28 37 00 00 0a 3a 12 00 00 00 07 28 1d 00 00 06 28 38 00 00 0a 07 28 39 00 00 0a 26 07 28 37 00 00 0a 39 0e 00 00 00 07 18 28 3a 00 00 0a 07 28 39 00 00 0a 26 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ART_2147841221_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ART!MTB"
        threat_id = "2147841221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 fe 01 13 07 11 07 2c 02 17 0c 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 09 02 11 05 17 28 ?? 00 00 0a 28 ?? 00 00 0a 06 07 d8 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 08 17 d6 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ATR_2147841222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ATR!MTB"
        threat_id = "2147841222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {19 0b 02 0d 16 13 04 2b 2b 09 11 04 6f ?? ?? ?? 0a 13 05 08 11 05 28 ?? ?? ?? 0a 07 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 00 11 04 17 d6 13 04 11 04 09 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARV_2147841421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARV!MTB"
        threat_id = "2147841421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 12 02 1f 64 14 0d 12 03 1f 64 28 ?? ?? ?? 06 2c 08 72 ?? ?? ?? 70 0a de 1c 07 17 ?? 0b 07 1a 31 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARV_2147841421_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARV!MTB"
        threat_id = "2147841421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 1b 08 68 07 1f 64 06 1f 64 28 ?? ?? ?? 06 2c 08 72 ?? ?? ?? 70 0d de 13 08 17 58 0c 08 1a 31 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 14 0b 16 0c 16 0d 16 13 04 14 13 05 16 13 06 06 07 08 12 06 12 03 12 04 11 05 16 28 ?? 00 00 06 26 11 06 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARV_2147841421_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARV!MTB"
        threat_id = "2147841421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 7b 00 00 04 08 7e 79 00 00 04 06 7e 75 00 00 04 08 28 ?? ?? ?? 06 1e 5b 28 ?? ?? ?? 06 16 2c 79 26 26 26 7e 7d 00 00 04 08 7e 79 00 00 04 06 7e 77 00 00 04 08 28}  //weight: 2, accuracy: Low
        $x_1_2 = "WinWord.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_AAF_2147846137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.AAF!MTB"
        threat_id = "2147846137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 59 13 06 2b 20 00 07 06 11 06 6f 0b 00 00 0a 13 07 12 07 28 0c 00 00 0a 28 0d 00 00 0a 0b 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 08 11 08 2d d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_RPY_2147895226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.RPY!MTB"
        threat_id = "2147895226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Falastin" ascii //weight: 1
        $x_1_2 = {a2 0b 05 18 d6 0c 14 0d 09 ?? ?? ?? ?? ?? 13 04 03 4a 04 4a d8 1f 58 d8 08 d6 16 d8 16 d6 13 05 02}  //weight: 1, accuracy: Low
        $x_1_3 = {00 03 8e 69 1f 11 da 17 d6 ?? ?? ?? ?? ?? 13 04 03 1f 10 11 04 16 03 8e 69 1f 10 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_KAA_2147895801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.KAA!MTB"
        threat_id = "2147895801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 04 16 11 04 8e 69 6f ?? ?? 00 0a 13 07 11 07 0a de 1c 00 11 06 2c 08 11 06 6f ?? 00 00 0a 00 dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_UXA_2147896147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.UXA!MTB"
        threat_id = "2147896147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 19 00 00 0a 0b 73 19 00 00 0a 0c 02 28 ?? ?? ?? 06 03 15 17 28 ?? ?? ?? 0a 0d 07 02 16 09 16 9a 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_3 = "SELECT * FROM FirewallProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_WZI_2147896148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.WZI!MTB"
        threat_id = "2147896148"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 0a 7e 18 00 00 0a 0b 06 6f ?? ?? ?? 0a 17 59 13 06 2b 20 00 07 06 11 06 6f ?? ?? ?? 0a 13 07 12 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 11 06 17 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARR_2147896938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARR!MTB"
        threat_id = "2147896938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0c 08 16 02 7b ?? 00 00 04 28 ?? 00 00 0a a2 08 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARR_2147896938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARR!MTB"
        threat_id = "2147896938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 13 07 28 ?? 00 00 0a 0d 19 13 07 17 28 ?? 00 00 0a 1f 20 17 19 15 28 ?? 00 00 0a 1a 13 07 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0a 1b 13 07 17 12 00 15 6a 16 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARR_2147896938_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARR!MTB"
        threat_id = "2147896938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Orichalque\\Dofus" wide //weight: 1
        $x_1_2 = "Orichalqueupdater" wide //weight: 1
        $x_1_3 = "Orichalque-Uplauncher\\obj\\Release\\Orichalqueupdater.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARR_2147896938_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARR!MTB"
        threat_id = "2147896938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 09 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 07 11 07 16 11 06 16 1f 10 28 ?? 00 00 0a 11 07 16 11 06 1f 0f 1f 10 28 ?? 00 00 0a 06 11 06 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 05 03 13 04 11 05 11 04 16 11 04 8e b7 6f ?? 00 00 0a 0c 08 0b de 0f}  //weight: 1, accuracy: Low
        $x_2_2 = "CACAO.trololo" wide //weight: 2
        $x_3_3 = "BETISE" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARR_2147896938_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARR!MTB"
        threat_id = "2147896938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 17 12 00 15 6a 16 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 17 9e 28 ?? 00 00 0a 02 06 02 7b ?? 00 00 04 28 ?? 00 00 0a 15 16 28}  //weight: 2, accuracy: Low
        $x_1_2 = "taskkill /f /IM ProcessHacker.exe" wide //weight: 1
        $x_1_3 = "taskkill /f /IM Tcpview.exe" wide //weight: 1
        $x_1_4 = "taskkill /f /IM Fiddler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARR_2147896938_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARR!MTB"
        threat_id = "2147896938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 07 b5 1f 64 28 ?? ?? ?? 0a 0d 12 03 1f 64 14 13 04 12 04 1f 64 28 ?? ?? ?? 06 13 05 11 05 2c 08 ?? ?? ?? ?? ?? 0a de 28 00 00 07 17 d6 0b 07 1a 13 06}  //weight: 2, accuracy: Low
        $x_1_2 = "RunFileFromLink" wide //weight: 1
        $x_1_3 = "RunFileFromDisk" wide //weight: 1
        $x_1_4 = "EncryptHostPort" wide //weight: 1
        $x_1_5 = "MessgboxFakeCheck" wide //weight: 1
        $x_1_6 = "StartupCheack" wide //weight: 1
        $x_1_7 = "InstallinShulderTask" wide //weight: 1
        $x_1_8 = "SCHTaskTiem" wide //weight: 1
        $x_1_9 = "HideAfterRun" wide //weight: 1
        $x_1_10 = "InstallIno" wide //weight: 1
        $x_1_11 = "Installinop" wide //weight: 1
        $x_3_12 = "Revenge-RAT" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_AREV_2147900446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.AREV!MTB"
        threat_id = "2147900446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 2d 16 06 28 ?? 00 00 06 17 28 ?? 00 00 0a 20 ?? 07 00 00 28 ?? 00 00 0a 72 ?? 01 00 70 72 ?? 01 00 70 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_3 = "SELECT * FROM FirewallProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARA_2147901237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARA!MTB"
        threat_id = "2147901237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 0a 03 06 17 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 07 02 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 11 05 09 d8 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 06 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARA_2147901237_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARA!MTB"
        threat_id = "2147901237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0b 16 0c 16 13 06 2b 5a 00 07 17 58 20 ff 00 00 00 5f 0b 08 11 04 07 e0 95 58 20 ff 00 00 00 5f 0c 11 04 07 e0 95 0d 11 04 07 e0 11 04 08 e0 95 9e 11 04 08 e0 09 9e 11 05 11 06 02 11 06 91 11 04 11 04 07 e0 95 11 04 08 e0 95 58 20 ff 00 00 00 5f e0 95 61 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_AR_2147901418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.AR!MTB"
        threat_id = "2147901418"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 16 6a 2b 64 00 07 16 17 73 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 1f 40 8d ?? 00 00 01 2b 3f 15 13 05 08 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 2b 1c 09 11 04 16 11 05 6f ?? 00 00 0a 00 08 11 04 16 11 04 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRat_ARG_2147946144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRat.ARG!MTB"
        threat_id = "2147946144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 0c 2b 30 02 08 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 0d 06 09 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 08 17 d6 0c 08 11 04 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

