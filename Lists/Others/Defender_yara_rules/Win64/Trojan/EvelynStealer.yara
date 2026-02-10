rule Trojan_Win64_EvelynStealer_GVA_2147962676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EvelynStealer.GVA!MTB"
        threat_id = "2147962676"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EvelynStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WindowStyle Hidden" wide //weight: 1
        $x_2_2 = "://syn1112223334445556667778889990.org/" wide //weight: 2
        $x_1_3 = "Start-Process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EvelynStealer_GVC_2147962721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EvelynStealer.GVC!MTB"
        threat_id = "2147962721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EvelynStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 b9 41 00 00 00 f3 48 ab 48 8d 84 24 20 05 00 00 b9 04 01 00 00 48 89 44 24 68 48 89 c2 48 8b 05 72 28 16 00 48 89 84 24 a8 00 00 00 ff d0 83 e8 01 89 84 24 80 00 00 00 3d 02 01 00 00 0f 87 91 13 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "app_bound_encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EvelynStealer_GVD_2147962722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EvelynStealer.GVD!MTB"
        threat_id = "2147962722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EvelynStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Evelyn" ascii //weight: 1
        $x_1_2 = "myetherwallet" wide //weight: 1
        $x_1_3 = "Copying wallets to Evelyn\\Wallets" ascii //weight: 1
        $x_1_4 = "Sensitive_Files" wide //weight: 1
        $x_1_5 = "/public_html/abe_decrypt.dll" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Hyper-V" wide //weight: 1
        $x_1_7 = "server09.mentality.cloud" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

