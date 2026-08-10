rule Trojan_Win32_PdfSider_EM_2147975842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PdfSider.EM!MTB"
        threat_id = "2147975842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PdfSider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "573d2149-b7b1-4d54-b0d4-403195f3984e" ascii //weight: 1
        $x_1_2 = "IsNativeVhdBoot" ascii //weight: 1
        $x_1_3 = "\"name\": \"%s\", \"build_date\": \"%s %s\", \"arch\": \"windows\", \"username\": \"%s\", \"pid\": \"%d\"" ascii //weight: 1
        $x_1_4 = "AES-256/GCM" ascii //weight: 1
        $x_1_5 = "Botan 3.0.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

