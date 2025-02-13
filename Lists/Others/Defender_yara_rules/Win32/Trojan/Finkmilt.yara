rule Trojan_Win32_Finkmilt_A_2147643115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Finkmilt.gen!A"
        threat_id = "2147643115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Finkmilt"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 4d 08 ff 75 08 e8 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "ldr.dll,Infiltrate" ascii //weight: 1
        $x_1_3 = "sgope.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Finkmilt_B_2147650740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Finkmilt.gen!B"
        threat_id = "2147650740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Finkmilt"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 4d 08 ff 75 08 e8 ?? ff ff ff}  //weight: 3, accuracy: Low
        $x_1_2 = "ldr.dll,prkt" ascii //weight: 1
        $x_1_3 = "nopor.sys" ascii //weight: 1
        $x_1_4 = "dopop.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Finkmilt_B_2147655216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Finkmilt.B!dll"
        threat_id = "2147655216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Finkmilt"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 64 72 2e 65 78 65 00 50 72 6b 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b d2 90 8b d2 8b d2 68 3f 00 0f 00 8b d2 90 6a 00 8b d2 90 6a 00 90 ff d0 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

