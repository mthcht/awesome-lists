rule Trojan_Win64_VBVStealer_PA_2147971400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VBVStealer.PA!MTB"
        threat_id = "2147971400"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VBVStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "====== VBV Stealer Report ======" ascii //weight: 4
        $x_1_2 = "\\Electrum\\wallets\\" ascii //weight: 1
        $x_1_3 = "--- COOKIES (" ascii //weight: 1
        $x_1_4 = "--- CLIPBOARD (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

