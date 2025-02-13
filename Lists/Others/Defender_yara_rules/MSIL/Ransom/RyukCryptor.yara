rule Ransom_MSIL_RyukCryptor_2147767649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RyukCryptor!MTB"
        threat_id = "2147767649"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RyukCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cf_antiLeak_Server" ascii //weight: 1
        $x_1_2 = "cf_use_fake_user" ascii //weight: 1
        $x_1_3 = "cf_use_fake_pass" ascii //weight: 1
        $x_1_4 = "allowFirewall" ascii //weight: 1
        $x_1_5 = "DELETEACCOUNT" ascii //weight: 1
        $x_1_6 = "CHECKREGEDIT" ascii //weight: 1
        $x_1_7 = "ADDACOUNT" ascii //weight: 1
        $x_1_8 = "init_BypassU" ascii //weight: 1
        $x_1_9 = "PAGE_EXECUTE_READWRITE" ascii //weight: 1
        $x_1_10 = "WM_KEYDOWN" ascii //weight: 1
        $x_1_11 = "WM_KEYUP" ascii //weight: 1
        $x_1_12 = "WM_SYSKEYDOWN" ascii //weight: 1
        $x_1_13 = "WM_SYSKEYUP" ascii //weight: 1
        $x_1_14 = "keyboardHookProc" ascii //weight: 1
        $x_1_15 = "prm_key" ascii //weight: 1
        $x_1_16 = "prm_text_to_decrypt" ascii //weight: 1
        $x_1_17 = "DllInjectionResult" ascii //weight: 1
        $x_1_18 = "CreateRemoteThread" ascii //weight: 1
        $x_1_19 = "killProcess" ascii //weight: 1
        $x_1_20 = "PROCESS_QUERY_INFORMATION" ascii //weight: 1
        $x_1_21 = "PROCESS_VM_READ" ascii //weight: 1
        $x_1_22 = "PROCESS_BASIC_INFORMATION" ascii //weight: 1
        $x_1_23 = "INTERNET_OPTION_SETTINGS_CHANGED" ascii //weight: 1
        $x_1_24 = "SELECT Caption FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_25 = "SetDNSServerSearchOrder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

