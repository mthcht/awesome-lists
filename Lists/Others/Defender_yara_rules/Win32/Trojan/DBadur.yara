rule Trojan_Win32_DBadur_GPA_2147904985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DBadur.GPA!MTB"
        threat_id = "2147904985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x-scripts.online/file" ascii //weight: 1
        $x_1_2 = "A_ScriptDir" ascii //weight: 1
        $x_1_3 = "URLDownloadToFile" ascii //weight: 1
        $x_1_4 = "injectData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DBadur_AHB_2147969439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DBadur.AHB!MTB"
        threat_id = "2147969439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Secedit /configure /cfg \"security.inf\" /db secsetup.sdb /areas USER_RIGHTS /verbose" ascii //weight: 30
        $x_20_2 = "HRZR_EHAPCY:\"P:\\JVAQBJF\\flfgrz32\\sverjnyy.pcy\",Jvaqbjf" ascii //weight: 20
        $x_10_3 = "HRZR_EHAPCY\"=hex:0C,00,00,00,2A,00,00,00,90,AF,A4,87,A4,95,C6,01" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

