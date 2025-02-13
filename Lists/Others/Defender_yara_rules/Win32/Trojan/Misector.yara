rule Trojan_Win32_Misector_A_2147646105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Misector.A"
        threat_id = "2147646105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Misector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\retail\\pos\\BioCertFiles\\BioertPath2.reg" ascii //weight: 1
        $x_1_2 = "sunseng%c%c%i.%i.%i.zip" ascii //weight: 1
        $x_1_3 = "ownemail" ascii //weight: 1
        $x_1_4 = "dugras@sendspace.com" ascii //weight: 1
        $x_1_5 = "recpemail" ascii //weight: 1
        $x_1_6 = "valeristar@e1.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Misector_B_2147650294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Misector.B"
        threat_id = "2147650294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Misector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":%s%c%c%i.%i.zip" ascii //weight: 1
        $x_1_2 = "frontend.exe" ascii //weight: 1
        $x_1_3 = "sendspace.com" ascii //weight: 1
        $x_1_4 = "uploadgetinfo&api_key=%s" ascii //weight: 1
        $x_1_5 = "valeristar@e1.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

