rule Trojan_Win32_DeathStalker_A_2147954071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DeathStalker.A"
        threat_id = "2147954071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DeathStalker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe " ascii //weight: 1
        $x_1_2 = "list " ascii //weight: 1
        $x_1_3 = "shadows" ascii //weight: 1
        $n_1_4 = "9453e881-26a8-4973-ba2e-76269e901d0e" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_DeathStalker_A_2147954071_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DeathStalker.A"
        threat_id = "2147954071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DeathStalker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msxsl.exe " ascii //weight: 1
        $x_1_2 = "payload.xml" ascii //weight: 1
        $x_1_3 = "payload.xsl" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $n_1_5 = "9453e881-26a8-4973-ba2e-76269e901d0d" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_DeathStalker_B_2147954075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DeathStalker.B"
        threat_id = "2147954075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DeathStalker"
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
        $n_1_6 = "9453e881-26a8-4973-ba2e-76269e901d0i" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

