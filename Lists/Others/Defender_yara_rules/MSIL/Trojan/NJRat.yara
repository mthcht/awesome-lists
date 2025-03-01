rule Trojan_MSIL_NJRat_SR_2147756887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.SR!MTB"
        threat_id = "2147756887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exceptiona firewall delete allowedprogram" ascii //weight: 1
        $x_1_2 = "/c ping 0 -n 2 & del" ascii //weight: 1
        $x_1_3 = "duckapp.duckdns.org" ascii //weight: 1
        $x_1_4 = "\\log.txt" ascii //weight: 1
        $x_1_5 = "HACKITUP" ascii //weight: 1
        $x_1_6 = "Co%nect" ascii //weight: 1
        $x_1_7 = "#ystem$rive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_NJRat_TW_2147762573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.TW!MTB"
        threat_id = "2147762573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6d 46 79 [0-21] 42 75 5a 58 63 67 51 57 4e 30 61 58 5a 6c 57 45 39 69 61 6d 56 6a 64 43 67 69 55 32 68 6c 62 47 77 75 51 58 42 77 62 47 6c 6a 59 58 52 70 62 32 34 69 4b 54 73 4e [0-21] 55 32 68 6c 62 47 78 46 65 47 56 6a 64 58 52 6c 4b 43 4a 36 65 69 49 73 49 43 49 69 4c 43 41 69 49 69 77 67 49 6b 39 77 5a 57 34 69 4c 43 41 69 4d 53 49 70 4f 77}  //weight: 1, accuracy: Low
        $x_1_2 = "HiddenSTUp" ascii //weight: 1
        $x_1_3 = "\\oi.com.js" ascii //weight: 1
        $x_1_4 = "\\oi.com.lnk" ascii //weight: 1
        $x_1_5 = "\\AVG\\Antivirus\\AVGUI.exe" ascii //weight: 1
        $x_1_6 = "\\AVAST Software\\Avast\\avastUI.exe" ascii //weight: 1
        $x_1_7 = "\\KasperSky Lab\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_MSIL_NJRat_RS_2147837788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.RS!MTB"
        threat_id = "2147837788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7e 0a 00 00 04 07 09 16 6f 2c 00 00 0a 13 04 12 04 28 2d 00 00 0a 6f 2e 00 00 0a 00 09 17 d6 0d 09 08 31 dc}  //weight: 5, accuracy: High
        $x_5_2 = {7e 0a 00 00 04 6f 2f 00 00 0a 28 14 00 00 06 26 de 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NJRat_RS_2147837788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.RS!MTB"
        threat_id = "2147837788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 44 00 00 0a 17 da 2b 2c 16 0d 2b 2b 7e 0d 00 00 04 07 09 16 6f 45 00 00 0a 13 04 12 04 28 46 00 00 0a 2b 03}  //weight: 2, accuracy: High
        $x_2_2 = {09 17 d6 0d 2b 03 0c 2b d1 09 08 31 02 2b 05 2b cd 0b 2b bc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NJRat_RPZ_2147844311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.RPZ!MTB"
        threat_id = "2147844311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 00 06 1f 0c 58 06 1f 0c 58 4a 17 d6 54 06 1f 10 58 06 1f 0c 58 4a 11 04 8e 69 fe 04 52 06 1f 10 58 46 2d ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NJRat_RPZ_2147844311_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.RPZ!MTB"
        threat_id = "2147844311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 0a 8f 0b 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd 11 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = "(-_-)zzz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NJRat_ARA_2147892012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.ARA!MTB"
        threat_id = "2147892012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 09 11 04 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 05 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 11 05 28 ?? ?? ?? 0a 00 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 00 11 04 18 58 13 04 11 04 09 28 ?? ?? ?? 2b 17 59 fe 04 13 07 11 07 2d af}  //weight: 2, accuracy: Low
        $x_2_2 = "\\obj\\Debug\\StubBinder.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NJRat_ARA_2147892012_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NJRat.ARA!MTB"
        threat_id = "2147892012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$07dcdb0c-ffd7-4bb2-ae1e-3760ce7cfca2" ascii //weight: 2
        $x_2_2 = "\\Binder By Ox muhammed\\stub\\obj\\x86\\Release\\stub.pdb" ascii //weight: 2
        $x_2_3 = "stub.exe" ascii //weight: 2
        $x_2_4 = "stub.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

