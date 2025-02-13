rule Trojan_Win32_Airostor_A_2147626863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Airostor.A"
        threat_id = "2147626863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Airostor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iuuq;00" wide //weight: 1
        $x_1_2 = "cmd /c ping 127.0.0.1 -n 3 && del " wide //weight: 1
        $x_1_3 = "tongji/g.asp?mac=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Airostor_B_2147627910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Airostor.B"
        threat_id = "2147627910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Airostor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 2d 01 00 8d 4d a4 0f ?? ?? 00 00 00 0f bf c0 50 51}  //weight: 2, accuracy: Low
        $x_2_2 = "g.asp?mac=" wide //weight: 2
        $x_2_3 = "\\Internet Exp1orer.lnk" wide //weight: 2
        $x_1_4 = "iuuq;00" wide //weight: 1
        $x_1_5 = "MyiQ.exe" wide //weight: 1
        $x_1_6 = "benjo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

