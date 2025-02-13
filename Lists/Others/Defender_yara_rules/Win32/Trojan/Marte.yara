rule Trojan_Win32_Marte_CAMP_2147847490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Marte.CAMP!MTB"
        threat_id = "2147847490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JkafoaesjgfiaJiagfieajg" ascii //weight: 1
        $x_1_2 = "Noasgioeasjgss" ascii //weight: 1
        $x_1_3 = "LroZOBXuwImVavpYtXYgXIBGJBh" ascii //weight: 1
        $x_1_4 = "nfNkMDKmZbESFBxZZhb" ascii //weight: 1
        $x_1_5 = "PegHYsViuwmHKeVERgy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Marte_AABY_2147849187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Marte.AABY!MTB"
        threat_id = "2147849187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FGioofiaeiejg" ascii //weight: 1
        $x_1_2 = "Fgisoegioaegjadf" ascii //weight: 1
        $x_1_3 = "NoiaiofgaejgajDoagd" ascii //weight: 1
        $x_1_4 = "Oioapfjioadjfgdj" ascii //weight: 1
        $x_1_5 = "Padfpoiajgiaedjgj" ascii //weight: 1
        $x_1_6 = "Yitisagiasegaisdokx" ascii //weight: 1
        $x_1_7 = "oioaidfjaoeighauehg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Marte_CCAL_2147890125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Marte.CCAL!MTB"
        threat_id = "2147890125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y829KPssFVtpdQ6quAO" wide //weight: 1
        $x_1_2 = "Ry6kpZzYe9995PcH19O1gQiQp" wide //weight: 1
        $x_1_3 = "3tPpY4s2xrRJvq34k2iqJMM" wide //weight: 1
        $x_1_4 = "Vf7yLZ7dww9aqP5Z27y" wide //weight: 1
        $x_1_5 = "7tSjP2q1NZzi7yuS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Marte_AMR_2147892968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Marte.AMR!MTB"
        threat_id = "2147892968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 b0 80 a8 41 00 1c 40 3d 04 30 07 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Marte_CCHZ_2147905382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Marte.CCHZ!MTB"
        threat_id = "2147905382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 68 70 02 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

