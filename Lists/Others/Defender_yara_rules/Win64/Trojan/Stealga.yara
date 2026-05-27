rule Trojan_Win64_Stealga_DD_2147963408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealga.DD!MTB"
        threat_id = "2147963408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Stealer\\x64\\Release\\" ascii //weight: 10
        $x_1_2 = "DECRYPTED KEY:" ascii //weight: 1
        $x_1_3 = "NotGoodShit" ascii //weight: 1
        $x_1_4 = ".\\pipe\\GetData" ascii //weight: 1
        $x_1_5 = "[*] Key saved to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealga_MK_2147970291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealga.MK!MTB"
        threat_id = "2147970291"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "powershell -NoProfile -Command \"Get-ChildItem '%s\\Microsoft\\Windows\\*.exe' -Hidden -Force -EA SilentlyContinue" ascii //weight: 15
        $x_10_2 = "Self destruct: all traces removed" ascii //weight: 10
        $x_5_3 = "mason_keylog_start" ascii //weight: 5
        $x_3_4 = "mason_persist_check" ascii //weight: 3
        $x_2_5 = "mason_av_check" ascii //weight: 2
        $x_1_6 = "mason_usb_dump" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

