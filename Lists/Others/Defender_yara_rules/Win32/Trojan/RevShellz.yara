rule Trojan_Win32_RevShellz_Z_2147949790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShellz.Z!MTB"
        threat_id = "2147949790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TCPClient($" wide //weight: 1
        $x_1_2 = ".GetStream(" wide //weight: 1
        $x_1_3 = "IO.StreamReader($" wide //weight: 1
        $x_1_4 = ".Read($" wide //weight: 1
        $x_1_5 = ".GetString($" wide //weight: 1
        $x_1_6 = "New-Object System.Byte[]" wide //weight: 1
        $x_1_7 = "while ($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RevShellz_ZA_2147949791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShellz.ZA!MTB"
        threat_id = "2147949791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TCPClient($" wide //weight: 1
        $x_1_2 = "Start-Job -ScriptBlock" wide //weight: 1
        $x_1_3 = "Set-Variable -Name" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RevShellz_B_2147955908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShellz.B!MTB"
        threat_id = "2147955908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".getstream(" wide //weight: 1
        $x_1_2 = ".streamwriter($" wide //weight: 1
        $x_1_3 = ".read($" wide //weight: 1
        $x_1_4 = ".getstring($" wide //weight: 1
        $x_1_5 = ".length);$" wide //weight: 1
        $x_1_6 = "new-objectsystem.byte[]" wide //weight: 1
        $x_1_7 = "};while($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

