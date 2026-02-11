rule Trojan_Win32_PhantomStealer_DA_2147960717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PhantomStealer.DA!MTB"
        threat_id = "2147960717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 10, accuracy: Low
        $x_1_2 = "$env:appdata+" wide //weight: 1
        $x_1_3 = "-join '';.($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PhantomStealer_RV_2147962880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PhantomStealer.RV!MTB"
        threat_id = "2147962880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "legitimatizes stadiometer" ascii //weight: 1
        $x_1_2 = "trilabe foretagender promagistrate" ascii //weight: 1
        $x_1_3 = "aberrative" ascii //weight: 1
        $x_1_4 = "fremavle.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

