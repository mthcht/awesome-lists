rule Trojan_Win64_Gofot_SX_2147959806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gofot.SX!MTB"
        threat_id = "2147959806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gofot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[+] Injection Process" ascii //weight: 10
        $x_5_2 = "[+] Emulator Detected" ascii //weight: 5
        $x_5_3 = "[+] Updated Codes" ascii //weight: 5
        $x_1_4 = "[+] Checking Updates" ascii //weight: 1
        $x_1_5 = "[-] Update failed, retrying" ascii //weight: 1
        $x_1_6 = "[+] Process Detected" ascii //weight: 1
        $x_1_7 = "[-] Main module missing, re-downloading" ascii //weight: 1
        $x_1_8 = "[+] Successfully Loaded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

