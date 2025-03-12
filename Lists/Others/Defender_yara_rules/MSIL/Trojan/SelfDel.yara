rule Trojan_MSIL_SelfDel_SG_2147904338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDel.SG!MTB"
        threat_id = "2147904338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adsbc.exe" ascii //weight: 1
        $x_1_2 = "get_ExecutablePath" ascii //weight: 1
        $x_1_3 = "adsbc.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SelfDel_SGA_2147907025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDel.SGA!MTB"
        threat_id = "2147907025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C ping 1.1.1.1 -n 2 -w 1000 > Nul & Del" wide //weight: 1
        $x_1_2 = "Klis.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SelfDel_ND_2147923390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDel.ND!MTB"
        threat_id = "2147923390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 3d 00 00 70 72 4c 01 00 70 1a 1f 30 28 5e 00 00 0a 1c 33 18 04 17 6f ?? 00 00 0a 02 28 ?? 00 00 0a 73 ?? 00 00 06 6f ?? 00 00 06 2a 04 17 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "/C timeout /T 2 /nobreak >nul & del" ascii //weight: 1
        $x_1_4 = "msinfo32.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SelfDel_NS_2147928606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDel.NS!MTB"
        threat_id = "2147928606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 72 59 18 00 70 7d 06 00 00 04 02 28 ?? 00 00 0a 0a 12 00 fe ?? ?? 00 00 01 6f ?? 00 00 0a 7d 07 00 00 04 02 72 09 18 00 70 d0 03 00 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 73 1b 00 00 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "taskkill /f /im" wide //weight: 1
        $x_1_3 = "newFrontTools.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SelfDel_GTN_2147935811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDel.GTN!MTB"
        threat_id = "2147935811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 91 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 5d 13 04 06 09 72 ?? ?? ?? 70 11 04 28 ?? ?? ?? 0a 9d 09 17 58 0d 09 02 32 d9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

