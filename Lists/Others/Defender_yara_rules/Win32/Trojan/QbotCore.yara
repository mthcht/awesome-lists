rule Trojan_Win32_QbotCore_A_2147763222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotCore.A!MTB"
        threat_id = "2147763222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbg_%s_%u_qbotdll.txt" ascii //weight: 1
        $x_1_2 = "qbot_dll_main" ascii //weight: 1
        $x_1_3 = "InitCoreData(): COREFLAG_LOAD_DLL_FROM_MEM wszQbotinjExePath=" ascii //weight: 1
        $x_1_4 = "InitCoreData(): COREFLAG_LOAD_QBOT_HOOK wszQbotinjExePath=" ascii //weight: 1
        $x_1_5 = "InitCoreData(): szSid='%s' wszUserName='%S' wszDomainName='%S' wszQbotinjExe='%S' wszHomeDir='%S' szVarsMutex='%s' szBaseRandomName='%s'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QbotCore_A_2147763669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotCore.A!!Qbot.gen!MTB"
        threat_id = "2147763669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotCore"
        severity = "Critical"
        info = "Qbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbg_%s_%u_qbotdll.txt" ascii //weight: 1
        $x_1_2 = "qbot_dll_main" ascii //weight: 1
        $x_1_3 = "InitCoreData(): COREFLAG_LOAD_DLL_FROM_MEM wszQbotinjExePath=" ascii //weight: 1
        $x_1_4 = "InitCoreData(): COREFLAG_LOAD_QBOT_HOOK wszQbotinjExePath=" ascii //weight: 1
        $x_1_5 = "InitCoreData(): szSid='%s' wszUserName='%S' wszDomainName='%S' wszQbotinjExe='%S' wszHomeDir='%S' szVarsMutex='%s' szBaseRandomName='%s'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QbotCore_B_2147926706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotCore.B!MTB"
        threat_id = "2147926706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61}  //weight: 1, accuracy: High
        $x_1_2 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1}  //weight: 1, accuracy: High
        $x_1_3 = {8b c2 83 e0 0f 8a ?? ?? ?? ?? ?? 8d 0c 3a 32 04 0e 42 88 01 3b 55 0c 72 e7 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

