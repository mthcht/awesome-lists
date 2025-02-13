rule Trojan_Win32_Drixed_QD_2147794855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.QD!MTB"
        threat_id = "2147794855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_2 = "LdrGetProcedureA" ascii //weight: 3
        $x_3_3 = "PathRemoveBlanksW" ascii //weight: 3
        $x_3_4 = "IsBadHugeReadPtr" ascii //weight: 3
        $x_3_5 = "QueryUsersOnEncryptedFile" ascii //weight: 3
        $x_3_6 = "SHEnumerateUnreadMailAccountsW" ascii //weight: 3
        $x_3_7 = "hReachappear.1529ChromiumFacebook," ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drixed_QS_2147794942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.QS!MTB"
        threat_id = "2147794942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "&Th~s p5ggr6i c6jno; be" ascii //weight: 3
        $x_3_2 = "'bra,yEx?" ascii //weight: 3
        $x_3_3 = "WTSGetActiveConsoleSessionId" ascii //weight: 3
        $x_3_4 = "InSendMessageEx" ascii //weight: 3
        $x_3_5 = "UnregisterHotKey" ascii //weight: 3
        $x_3_6 = "CreateProcessAsUserW" ascii //weight: 3
        $x_3_7 = "ImpersonateLoggedOnUser" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drixed_QR_2147794943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.QR!MTB"
        threat_id = "2147794943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rpidebbfll.pdb" ascii //weight: 3
        $x_3_2 = "application.vNvstevereturn.theE" ascii //weight: 3
        $x_3_3 = "llosewwq.ll" ascii //weight: 3
        $x_3_4 = "tokenythesPepper" ascii //weight: 3
        $x_3_5 = "BlinkbfixedwasFebruarythatdisplayedWebRTC.75JY" ascii //weight: 3
        $x_3_6 = "ingExtensionspreviouslyusingY" ascii //weight: 3
        $x_3_7 = "Xaddtransferred2012,securityv" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drixed_QQ_2147794963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.QQ!MTB"
        threat_id = "2147794963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LdrGetProcedureAtarenIrmorrar891" ascii //weight: 3
        $x_3_2 = "zcorprnentcomputerrcressZa201r,lPwas" ascii //weight: 3
        $x_3_3 = "srhidden89.75%Junenormal" ascii //weight: 3
        $x_3_4 = "FFPGGLBM.pdb" ascii //weight: 3
        $x_3_5 = "yfamilyjbrowsersIron,9to3under" ascii //weight: 3
        $x_3_6 = "DeveloperZ8tospellingtop," ascii //weight: 3
        $x_3_7 = "sTheVnoSExplorerE6downloadas" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drixed_QE_2147795464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.QE!MTB"
        threat_id = "2147795464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xmrig" ascii //weight: 3
        $x_3_2 = "powrprof.dll" ascii //weight: 3
        $x_3_3 = "PowerRegisterSuspendResumeNotification" ascii //weight: 3
        $x_3_4 = "InvokeMainViaCRT" ascii //weight: 3
        $x_3_5 = "GetAdaptersAddresses" ascii //weight: 3
        $x_3_6 = "LookupPrivilegeValueW" ascii //weight: 3
        $x_3_7 = "WSASocketW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drixed_RPZ_2147846658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.RPZ!MTB"
        threat_id = "2147846658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 20 b9 02 00 00 00 e2 11 4a 4a 89 e8 50 8f 05 ?? ?? ?? ?? e9 31 fc ff ff c3 42 83 c2 07 29 c2 8d 05 ?? ?? ?? ?? 31 38 83 e8 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drixed_RPZ_2147846658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.RPZ!MTB"
        threat_id = "2147846658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 bd ff fe ff ff 54 89 85 f4 fe ff ff 75 4a 80 bd 00 ff ff ff 45 75 41 80 bd 01 ff ff ff 53 75 38 80 bd 02 ff ff ff 54 75 2f 80 bd 03 ff ff ff 41 75 26 80 bd 04 ff ff ff 50 75 1d 80 bd 05 ff ff ff 50 75 14 b8 01 00 00 00 80 bd 0a ff ff ff 00 89 85 f0 fe ff ff 74 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drixed_RPX_2147848433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drixed.RPX!MTB"
        threat_id = "2147848433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e4 62 c6 45 e5 92 c6 45 e6 9c c6 45 e7 e7 c6 45 e8 fd c6 45 e9 13 c6 45 ea a9 c6 45 eb d0 c6 45 ec 1c c6 45 ed b1}  //weight: 1, accuracy: High
        $x_1_2 = {f6 17 80 2f 7c 47 e2 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

