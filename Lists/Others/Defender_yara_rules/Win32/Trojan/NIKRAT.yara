rule Trojan_Win32_NIKRAT_2147982849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NIKRAT!atmn"
        threat_id = "2147982849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NIKRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "main.handleWifiSteal" ascii //weight: 3
        $x_2_2 = "main.handlePasswords" ascii //weight: 2
        $x_3_3 = "main.handleCommand.func1" ascii //weight: 3
        $x_2_4 = "main.sendResult.func1" ascii //weight: 2
        $x_2_5 = "main.screenStreamLoop.func1" ascii //weight: 2
        $x_1_6 = "main.encryptPayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NIKRAT_2147982849_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NIKRAT!atmn"
        threat_id = "2147982849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NIKRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "main.handleTokenGrab" ascii //weight: 3
        $x_3_2 = "main.handleCryptoSteal" ascii //weight: 3
        $x_3_3 = "main.handleBrowserWalletExport" ascii //weight: 3
        $x_3_4 = "main.handleCOMHijack" ascii //weight: 3
        $x_2_5 = "main.handleStealthMode" ascii //weight: 2
        $x_2_6 = "main.handleHVNCStart" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NIKRAT_2147982849_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NIKRAT!atmn"
        threat_id = "2147982849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NIKRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "main.handleWifiSteal" ascii //weight: 3
        $x_3_2 = "main.handlePasswords" ascii //weight: 3
        $x_2_3 = "main.wifiGrab" ascii //weight: 2
        $x_1_4 = "key4.db" ascii //weight: 1
        $x_3_5 = "main.handleCMD" ascii //weight: 3
        $x_2_6 = "main.quietCmd" ascii //weight: 2
        $x_2_7 = "main.wsConnect" ascii //weight: 2
        $x_2_8 = "main.pinnedTLSConfig" ascii //weight: 2
        $x_2_9 = "main.encryptPayload" ascii //weight: 2
        $x_2_10 = "main.decryptPayload" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

