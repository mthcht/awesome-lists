rule VirTool_Win32_Kekeo_B_2147805713_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Kekeo.B"
        threat_id = "2147805713"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kekeo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "base64(ticket.kirbi)" ascii //weight: 1
        $x_1_2 = "krbtgt/{0}" ascii //weight: 1
        $x_1_3 = "krbtgt/.*" ascii //weight: 1
        $x_1_4 = "/domain:" ascii //weight: 1
        $x_1_5 = "/impersonateuser" ascii //weight: 1
        $x_1_6 = "/krbkey" ascii //weight: 1
        $x_1_7 = "(!samAccountName=krbtgt)(!(UserAccountControl:" ascii //weight: 1
        $x_1_8 = {4b 72 62 43 72 65 64 00}  //weight: 1, accuracy: High
        $x_1_9 = "base64({0}.kirbi)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

