rule HackTool_Win32_PsCredinject_A_2147730301_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PsCredinject.A"
        threat_id = "2147730301"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PsCredinject"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Error calling LsaLogonUser. Error code:" ascii //weight: 1
        $x_1_2 = "Invoke-CredentialInjection" ascii //weight: 1
        $x_1_3 = "Call to LsaLookupAuthenticationPackage failed. Error" ascii //weight: 1
        $x_1_4 = "Error calling LsaConnectUntrusted. Error code" ascii //weight: 1
        $x_1_5 = "Logon succeeded, impersonating the token so it can be kidnapped and starting an infinite loop with the thread" ascii //weight: 1
        $x_1_6 = "\\\\.\\pipe\\sqsvc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_PsCredinject_A_2147730302_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PsCredinject.A!!PsCredinject.A"
        threat_id = "2147730302"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PsCredinject"
        severity = "High"
        info = "PsCredinject: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Error calling LsaLogonUser. Error code:" ascii //weight: 1
        $x_1_2 = "Invoke-CredentialInjection" ascii //weight: 1
        $x_1_3 = "Call to LsaLookupAuthenticationPackage failed. Error" ascii //weight: 1
        $x_1_4 = "Error calling LsaConnectUntrusted. Error code" ascii //weight: 1
        $x_1_5 = "Logon succeeded, impersonating the token so it can be kidnapped and starting an infinite loop with the thread" ascii //weight: 1
        $x_1_6 = "\\\\.\\pipe\\sqsvc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

