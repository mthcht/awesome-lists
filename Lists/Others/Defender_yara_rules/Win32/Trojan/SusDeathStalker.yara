rule Trojan_Win32_SusDeathStalker_A_2147955536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDeathStalker.A"
        threat_id = "2147955536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDeathStalker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe " ascii //weight: 1
        $x_1_2 = "list " ascii //weight: 1
        $x_1_3 = "shadows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusDeathStalker_A_2147955536_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDeathStalker.A"
        threat_id = "2147955536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDeathStalker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msxsl.exe " ascii //weight: 1
        $x_1_2 = "payload.xml" ascii //weight: 1
        $x_1_3 = "payload.xsl" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusDeathStalker_B_2147955540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDeathStalker.B"
        threat_id = "2147955540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDeathStalker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msxsl.exe " ascii //weight: 1
        $x_1_2 = "payload.xml" ascii //weight: 1
        $x_1_3 = "payload.xsl" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = "winver.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

