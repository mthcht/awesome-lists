rule Trojan_Win32_ScriptExec_A_2147924640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScriptExec.A"
        threat_id = "2147924640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScriptExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" ascii //weight: 1
        $x_1_2 = "Wscript.Shell" ascii //weight: 1
        $x_1_3 = "powershell.exe -nop -Command Write-Host AttackIQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ScriptExec_B_2147926860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScriptExec.B"
        threat_id = "2147926860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScriptExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "os get" ascii //weight: 1
        $x_1_3 = {2f 00 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 [0-4] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-128] 2e 00 78 00 73 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 66 6f 72 6d 61 74 3a [0-4] 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-128] 2e 78 73 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_ScriptExec_D_2147938497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScriptExec.D"
        threat_id = "2147938497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScriptExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "os get" ascii //weight: 1
        $x_1_3 = {2f 00 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 [0-90] 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-128] 2e 00 78 00 73 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 66 6f 72 6d 61 74 3a [0-90] 5c 74 65 6d 70 5c [0-128] 2e 78 73 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

