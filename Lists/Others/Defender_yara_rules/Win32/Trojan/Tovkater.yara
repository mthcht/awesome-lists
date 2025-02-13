rule Trojan_Win32_Tovkater_A_2147731356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tovkater.A"
        threat_id = "2147731356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tovkater"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\nsy28B8.tmp" wide //weight: 1
        $x_1_2 = "or.dll" wide //weight: 1
        $x_1_3 = "dfwert.exe" wide //weight: 1
        $x_1_4 = "Y gamemonitor.dll" wide //weight: 1
        $x_1_5 = "asdfwert.exe" wide //weight: 1
        $x_1_6 = "test.dll" wide //weight: 1
        $x_1_7 = "fghjrtyu.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tovkater_B_2147731360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tovkater.B"
        threat_id = "2147731360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tovkater"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\nsy28B8.tmp" wide //weight: 1
        $x_1_2 = "shmgrate.exe" wide //weight: 1
        $x_1_3 = "Y gamemonitor.dll" wide //weight: 1
        $x_1_4 = "zwert.exe" wide //weight: 1
        $x_1_5 = "msimn.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

