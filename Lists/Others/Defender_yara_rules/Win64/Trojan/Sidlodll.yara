rule Trojan_Win64_Sidlodll_DA_2147926704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sidlodll.DA!MTB"
        threat_id = "2147926704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sidlodll"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 48 8b c3 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 48 2b c8 49 0f af cf 0f b6 44 0d ?? 43 32 44 31 fc 41 88 41 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 c8 48 8b c3 48 f7 e1 48 c1 ea 04 48 6b c2 13 48 2b c8 49 0f af cf 0f b6 44 0d ?? 43 32 44 31 fc 41 88 41 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Sidlodll_DB_2147926705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sidlodll.DB!MTB"
        threat_id = "2147926705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sidlodll"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunShellcodeProc()" ascii //weight: 10
        $x_10_2 = "ReadPayloadFromDisc()" ascii //weight: 10
        $x_1_3 = "logger_init()" ascii //weight: 1
        $x_1_4 = "Client hook" ascii //weight: 1
        $x_1_5 = "c:\\debug_log\\" ascii //weight: 1
        $x_1_6 = "rc4Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sidlodll_DC_2147927628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sidlodll.DC!MTB"
        threat_id = "2147927628"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sidlodll"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell.exe -windowstyle Hidden -command \"%s\"" ascii //weight: 10
        $x_10_2 = "ExecuteScript" ascii //weight: 10
        $x_10_3 = {61 00 63 00 6c 00 75 00 69 00 [0-15] 2e 00 64 00 6c 00 6c 00}  //weight: 10, accuracy: Low
        $x_10_4 = {61 63 6c 75 69 [0-15] 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_1_5 = "ChildItem Variable:_).Value.Name-ilike'D*g'}).Name).Invoke((Item Variable:\\h).Value)" ascii //weight: 1
        $x_1_6 = "me).Invoke('*e-*press*',1,$TRUE))(Variable U3).Value.((Variable I16).Value).Invoke((Get-Variable 7 -Value))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

