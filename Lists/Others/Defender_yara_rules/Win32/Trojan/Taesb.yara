rule Trojan_Win32_Taesb_B_2147617143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taesb.B!dll"
        threat_id = "2147617143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taesb"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*\\AC:\\y0Za8\\wpad\\wpad.vbp" wide //weight: 10
        $x_5_2 = "wpad.dll" ascii //weight: 5
        $x_1_3 = {5a 68 10 de 02 11 68 14 de 02 11 52 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Taesb_C_2147617273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taesb.C"
        threat_id = "2147617273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taesb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*\\AC:\\ToeTQ8938S06e5bWy" wide //weight: 10
        $x_10_2 = "oyurzc" wide //weight: 10
        $x_1_3 = {5a 68 10 de 02 11 68 14 de 02 11 52 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

