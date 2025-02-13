rule Trojan_Win32_Fiefeer_A_2147617127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fiefeer.A"
        threat_id = "2147617127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiefeer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_imac=JFYDEKR47HE" wide //weight: 2
        $x_2_2 = "/porno/img/new/1a.gif" wide //weight: 2
        $x_2_3 = "pr9001" wide //weight: 2
        $x_2_4 = "{F3BA2A51-BB4F-4e22-AD0E-DFF956D5B672}" wide //weight: 2
        $x_1_5 = "background-image:url(http://" wide //weight: 1
        $x_1_6 = "__d.getTime()" wide //weight: 1
        $x_1_7 = "microsoft.data.xsl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fiefeer_A_2147617128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fiefeer.A"
        threat_id = "2147617128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiefeer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{4b01a5b8-8339-415b-a5f9-d87ca128df16}" wide //weight: 2
        $x_2_2 = "{F3BA2A51-BB4F-4e22-AD0E-DFF956D5B672}" wide //weight: 2
        $x_2_3 = "BP Data Feeder" wide //weight: 2
        $x_2_4 = "\\feeder.js" wide //weight: 2
        $x_2_5 = "djlib.dll" wide //weight: 2
        $x_2_6 = "\\DataFeeder.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Fiefeer_A_2147622472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fiefeer.gen!A"
        threat_id = "2147622472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiefeer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 2, accuracy: High
        $x_2_2 = {70 00 6f 00 72 00 6e 00 6f 00 2f 00 69 00 6d 00 67 00 2f 00 6e 00 65 00 77 00 2f 00 [0-2] 61 00 2e 00 67 00 69 00 66 00 29 00}  //weight: 2, accuracy: Low
        $x_1_3 = "microsoft.data.xsl" wide //weight: 1
        $x_1_4 = "background-image:url(http://" wide //weight: 1
        $x_1_5 = "pr9001" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

