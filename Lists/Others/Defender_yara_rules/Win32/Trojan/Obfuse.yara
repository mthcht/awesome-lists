rule Trojan_Win32_Obfuse_RA_2147755588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuse.RA!MTB"
        threat_id = "2147755588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YNoEf1Xw9XsoEh9yKDpUpBSFWRO210" wide //weight: 1
        $x_1_2 = "F6HltzMSRMheozYeu118" wide //weight: 1
        $x_1_3 = "KTMPoOK3LSa6Om4z6E63b62" wide //weight: 1
        $x_1_4 = "cwL40M8H1dBiyZpDuukYuLW7ms8YIQRfNdbj246" wide //weight: 1
        $x_1_5 = "gsTyRrSXOpRGQVBMRc6vbZ25" wide //weight: 1
        $x_1_6 = "Q8aeHLTrd6yMuBi9XQVm82qTLLzE231" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

