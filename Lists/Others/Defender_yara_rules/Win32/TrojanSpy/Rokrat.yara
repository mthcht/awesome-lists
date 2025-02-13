rule TrojanSpy_Win32_Rokrat_PA_2147772777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rokrat.PA!MTB"
        threat_id = "2147772777"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "login=%s&password=%s&login_submit=Authorizing...&dologin=1&client_id=%s&response_type=code&redirect_uri=%s&scope=" wide //weight: 1
        $x_1_2 = "consent_accept=Grant+access+to+Box&request_token" wide //weight: 1
        $x_1_3 = "&folder_id=&file_id=&parent_token=&parent_service_id=&service_action_id=&state=%s&doconsen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

