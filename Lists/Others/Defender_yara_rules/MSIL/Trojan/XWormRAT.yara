rule Trojan_MSIL_XWormRAT_B_2147840915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.B!MTB"
        threat_id = "2147840915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /im iexplore.exe" wide //weight: 2
        $x_2_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" wide //weight: 2
        $x_2_3 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA" wide //weight: 2
        $x_2_4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 2
        $x_2_5 = "shutdown.exe /f /s /t 0" wide //weight: 2
        $x_2_6 = "cmd.exe /c net stop wuauserv && sc config wuauserv start= disabled" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_C_2147843840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.C!MTB"
        threat_id = "2147843840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\root\\SecurityCenter2" wide //weight: 2
        $x_2_2 = "Select * from AntivirusProduct" wide //weight: 2
        $x_2_3 = "shutdown.exe /f /s /t 0" wide //weight: 2
        $x_2_4 = "shutdown.exe /f /r /t 0" wide //weight: 2
        $x_2_5 = "shutdown.exe -L" wide //weight: 2
        $x_2_6 = "-ExecutionPolicy Bypass -File" wide //weight: 2
        $x_2_7 = "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,45}\\b" wide //weight: 2
        $x_2_8 = "T[A-Za-z1-9]{33}" wide //weight: 2
        $x_2_9 = "\\b(0x)[a-zA-HJ-NP-Z0-9]{40,45}\\b" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_E_2147849620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.E!MTB"
        threat_id = "2147849620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? 00 00 0a 16 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 09 11 07 12 03 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_F_2147849968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.F!MTB"
        threat_id = "2147849968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 7e 5f 01 00 04 28 ?? ?? 00 06 14 14 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_G_2147891851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.G!MTB"
        threat_id = "2147891851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 04 16 73 ?? ?? 00 0a 0d 09 07 6f ?? ?? 00 0a 7e ?? 00 00 04 07 6f ?? ?? 00 0a 14 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {20 00 01 00 00 14 14 14 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_I_2147894381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.I!MTB"
        threat_id = "2147894381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 13 04 1b 0d 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_J_2147897380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.J!MTB"
        threat_id = "2147897380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 91 20 ?? ?? 00 00 28 ?? ?? 00 06 11 04 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 5d 28 ?? ?? 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 16 2d ?? 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_AAYY_2147898610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.AAYY!MTB"
        threat_id = "2147898610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 17 8d ?? 00 00 01 0c 08 16 07 8c ?? 00 00 01 a2 08 14 28 ?? 00 00 0a 1f 0e 8d ?? 00 00 01 13 04 11 04 16 20 f7 00 00 00 9e 11 04 17 1f 28 9e 11 04 18 1f 73 9e 11 04 19 20 b1 00 00 00 9e 11 04 1a 20 c7 00 00 00 9e 11 04 1b 20 8a 00 00 00 9e 11 04 1c 1f 6c 9e 11 04 1d 20 98 00 00 00 9e 11 04 1e 1f 23 9e 11 04 1f 09 20 ba 00 00 00 9e 11 04 1f 0a 20 ee 00 00 00 9e 11 04 1f 0b 1f 55 9e 11 04 1f 0c 20 8d 00 00 00 9e 11 04 1f 0d 20 b1 00 00 00 9e 11 04 07 1f 0e 5d 94 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 07 17 d6 0b 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_K_2147899086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.K!MTB"
        threat_id = "2147899086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AFkAdwBCAHQAQQBHAFEAQQBMAGcAQgBsAEEASABnAEEAWgBRAEEAPQ==" wide //weight: 2
        $x_2_2 = "AEwAdwBCAGoAQQBDAEEAQQBZAHcAQgB2AEEASABBAEEAZQBRAEEAZwBBA" wide //weight: 2
        $x_2_3 = "AFUAdwBCAHYAQQBHAFkAQQBkAEEAQgAzAEEARwBFAEEAYwBnAEIAbABBAEYAdwBBAFQAUQBCAHAAQQBHAE0AQQBjAGcAQgB2AEE" wide //weight: 2
        $x_2_4 = "ASABNAEEAYgB3AEIAbQBBAEgAUQBBAFgAQQBCAFgAQQBHAGsAQQBiAGcAQgBrAEEARwA4AEEAZAB3AEIAegBBAEYAdw" wide //weight: 2
        $x_2_5 = "AFUAdwBCAGwAQQBIAEkAQQBkAGcAQgBwAEEARwBNAEEAWgBRAEEAZwBBAEYATQBBAFkAdwBCAG8AQQ" wide //weight: 2
        $x_2_6 = "BHAFUAQQBaAEEAQgAxAEEARwB3AEEAWgBRAEIAeQBBAEEAPQA9" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_M_2147900688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.M!MTB"
        threat_id = "2147900688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "exe.llehsrewop\\0.1v\\llehsrewoPswodniW\\23metsyS\\swodniW:C" wide //weight: 2
        $x_2_2 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" wide //weight: 2
        $x_2_3 = "-WindowStyle Hidden Copy-Item -Path *.vbs -Destination" wide //weight: 2
        $x_2_4 = "C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_N_2147901325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.N!MTB"
        threat_id = "2147901325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" wide //weight: 2
        $x_2_3 = "-WindowStyle Hidden Copy-Item -Path *.vbs -Destination" wide //weight: 2
        $x_2_4 = "C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_O_2147902690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.O!MTB"
        threat_id = "2147902690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "-WindowStyle Hidden Copy-Item -Path *.js -Destination" wide //weight: 2
        $x_2_3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" wide //weight: 2
        $x_2_4 = "C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_P_2147902820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.P!MTB"
        threat_id = "2147902820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "-WindowStyle Hidden Copy-Item -Path *.vbs -Destination" wide //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_4 = "C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_Q_2147904981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.Q!MTB"
        threat_id = "2147904981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-WindowStyle Hidden Copy-Item -Path *.vbs -Destination" wide //weight: 2
        $x_2_2 = "exe.llehsrewop\\0.1v\\llehSrewoPswodniW\\23metsyS\\swodniW\\:C" wide //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_4 = "C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_S_2147905640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.S!MTB"
        threat_id = "2147905640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 df b6 3f 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3c 01 00 00 17 01 00 00 08 04 00 00 e1 0a}  //weight: 2, accuracy: High
        $x_2_2 = "CYQ.Data" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_R_2147906568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.R!MTB"
        threat_id = "2147906568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "-WindowStyle Hidden Copy-Item -Path *.vbs -Destination" wide //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_4 = "\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_V_2147907676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.V!MTB"
        threat_id = "2147907676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 8e 69 8d ?? 00 00 01 fe ?? ?? 00 fe ?? ?? 00 8e 69 fe ?? ?? 00 28 ?? 00 00 0a 3b ?? 00 00 00 fe ?? ?? 00 fe ?? ?? 00 28 ?? 00 00 0a fe ?? 00 00 a2 14 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_U_2147907783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.U!MTB"
        threat_id = "2147907783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 02 1a 58 11 04 16 08 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 7e ?? ?? 00 04 11 05 6f ?? 00 00 0a 7e ?? ?? 00 04 02 6f ?? 00 00 0a 7e ?? ?? 00 04 6f ?? 00 00 0a 17 59 28 ?? 00 00 0a 16 7e ?? ?? 00 04 02 1a 28 ?? 00 00 0a 11 05}  //weight: 2, accuracy: Low
        $x_2_2 = {57 bd a3 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 d3 00 00 00 fa 00 00 00 9f 04 00 00 f2 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_W_2147908321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.W!MTB"
        threat_id = "2147908321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 1a 5d 91 07 1a 5d 1e 5a 1f ?? 5f 63 d2 61 d2 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_X_2147908419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.X!MTB"
        threat_id = "2147908419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 11 06 d4 91 11 04 11 04 07 95 11 04 08 95 58 20 ?? ?? ?? ?? 5f 95 61 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_Y_2147908507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.Y!MTB"
        threat_id = "2147908507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 03 11 03 18 5a 7e ?? ?? 00 04 28 ?? ?? 00 06 6c 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XWormRAT_RP_2147912888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormRAT.RP!MTB"
        threat_id = "2147912888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "li3076EJQfTGAQPO7Zok2o" ascii //weight: 1
        $x_1_2 = "EPqfoXBWynpQEPogJ92qdMrm9HbvNSigt7qO9Jr" ascii //weight: 1
        $x_1_3 = "VTWr1BxIyBygII3sqKg0wi" ascii //weight: 1
        $x_1_4 = "ekCyLPxf9HPX06DKbbNOBgvkjaZ0MHB3TY8X9Rj" ascii //weight: 1
        $x_1_5 = "D4WRSn2y4ntigryAxbX5zi3nEeYayDPl4O2dtZk" ascii //weight: 1
        $x_1_6 = "XHJYDTw3pnYWwXSL5jLick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

