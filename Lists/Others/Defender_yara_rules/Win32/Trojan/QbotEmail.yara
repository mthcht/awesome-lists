rule Trojan_Win32_QbotEmail_A_2147763211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotEmail.A!MTB"
        threat_id = "2147763211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotEmail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "emailcollector_dll: DllMain(): got DLL_PROCESS_ATTACH x64" ascii //weight: 1
        $x_1_2 = "CollectOutlookData(): started nick=%s" ascii //weight: 1
        $x_1_3 = "collector_log.txt" ascii //weight: 1
        $x_1_4 = "\\email.txt" ascii //weight: 1
        $x_1_5 = "CollectOutlookEmails(): cannot detect current msg store email!!! Very bad!!!" ascii //weight: 1
        $x_1_6 = "addressbook.txt" ascii //weight: 1
        $x_1_7 = "cmd.exe /c rmdir /S /Q \"%s\"" ascii //weight: 1
        $x_1_8 = "%s\\EmailStorage_%s-%s_%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QbotEmail_A_2147763667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotEmail.A!!Qbot.gen!MTB"
        threat_id = "2147763667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotEmail"
        severity = "Critical"
        info = "Qbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "emailcollector_dll: DllMain(): got DLL_PROCESS_ATTACH x64" ascii //weight: 1
        $x_1_2 = "CollectOutlookData(): started nick=%s" ascii //weight: 1
        $x_1_3 = "collector_log.txt" ascii //weight: 1
        $x_1_4 = "\\email.txt" ascii //weight: 1
        $x_1_5 = "CollectOutlookEmails(): cannot detect current msg store email!!! Very bad!!!" ascii //weight: 1
        $x_1_6 = "addressbook.txt" ascii //weight: 1
        $x_1_7 = "cmd.exe /c rmdir /S /Q \"%s\"" ascii //weight: 1
        $x_1_8 = "%s\\EmailStorage_%s-%s_%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

