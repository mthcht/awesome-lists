rule Trojan_Win32_RunnySlip_A_2147764245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RunnySlip.A!dha"
        threat_id = "2147764245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RunnySlip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "windows-manifest-filename liQuid.exe.manifest" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RunnySlip_B_2147764246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RunnySlip.B!dha"
        threat_id = "2147764246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RunnySlip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "base64-5-step-tcp-shell-decode-execute-client" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

