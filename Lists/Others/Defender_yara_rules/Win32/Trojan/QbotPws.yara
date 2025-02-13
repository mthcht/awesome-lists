rule Trojan_Win32_QbotPws_A_2147763221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotPws.A!MTB"
        threat_id = "2147763221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotPws"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RipSavedPasses(): CoInitialize() failed" ascii //weight: 1
        $x_1_2 = "RipSavedPasses(): log_proc=NULL" ascii //weight: 1
        $x_1_3 = "CuteFtpPasswords(): started" ascii //weight: 1
        $x_1_4 = "EnumPStorage(): Outlook acc: [%s]=[%s]" ascii //weight: 1
        $x_1_5 = "DecryptEEPSData(): CryptUnprotectData() failed" ascii //weight: 1
        $x_1_6 = "ExtractIECredentials2()" ascii //weight: 1
        $x_1_7 = "decrypt_firefox_json()" ascii //weight: 1
        $x_1_8 = "OutlookDecryptPassword()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QbotPws_A_2147763668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotPws.A!!Qbot.gen!MTB"
        threat_id = "2147763668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotPws"
        severity = "Critical"
        info = "Qbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RipSavedPasses(): CoInitialize() failed" ascii //weight: 1
        $x_1_2 = "RipSavedPasses(): log_proc=NULL" ascii //weight: 1
        $x_1_3 = "CuteFtpPasswords(): started" ascii //weight: 1
        $x_1_4 = "EnumPStorage(): Outlook acc: [%s]=[%s]" ascii //weight: 1
        $x_1_5 = "DecryptEEPSData(): CryptUnprotectData() failed" ascii //weight: 1
        $x_1_6 = "ExtractIECredentials2()" ascii //weight: 1
        $x_1_7 = "decrypt_firefox_json()" ascii //weight: 1
        $x_1_8 = "OutlookDecryptPassword()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

