rule Trojan_Win32_Getawa_C_2147777797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Getawa.C!MTB"
        threat_id = "2147777797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Getawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "findstr \"WinRAR.exe\" > %temp%\\rarcek.txt" ascii //weight: 1
        $x_1_2 = "mkdir %temp%\\Peretasint" ascii //weight: 1
        $x_1_3 = "echo %computername% > %temp%\\Peretasint\\systeminfo+-Peretasint.txt" ascii //weight: 1
        $x_1_4 = "del getkeeplives.exe" ascii //weight: 1
        $x_1_5 = "del %windir%\\system32\\taskho-8.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

